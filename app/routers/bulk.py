import csv, io, json
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from app import auth
from app.config import MAX_IMPORT_BYTES, MAX_IMPORT_ROWS
from app.db import audit, connect
from app.services.rules import create_rule, list_networks, list_rules
from app.services.access_model import list_policy_groups
from app.security import normalize_domain, normalize_ip
router=APIRouter(prefix="/bulk")
def can_manage(u):return u and u["role"] in("admin","operator")
def _parse(content):
    lines=[x for x in content.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    if not lines:return []
    if "," in lines[0] and "destination" in lines[0].lower():return [dict(r) for r in csv.DictReader(io.StringIO("\n".join(lines)))]
    return [{"destination":x.strip()} for x in lines]
def _maps():
    nets=list_networks();m={}
    for n in nets:
        m[n["cidr"].lower()]=n["id"];m[n["name"].lower()]=n["id"]
        if n.get("vlan_id") is not None:
            m[str(n["vlan_id"]).lower()]=n["id"];m[("vlan"+str(n["vlan_id"])).lower()]=n["id"]
    return nets,m

def _group_map():
    groups=list_policy_groups();m={}
    for g in groups:
        m[str(g["id"]).lower()]=g["id"]
        m[g["name"].strip().lower()]=g["id"]
    return groups,m
def _scope(raw,defaults,m):
    if not raw:return list(defaults),[]
    ids=[];unknown=[]
    for token in [x.strip() for x in raw.replace("|",";").split(";") if x.strip()]:
        rid=m.get(token.lower())
        if rid is None:unknown.append(token)
        elif rid not in ids:ids.append(rid)
    return ids,unknown
@router.get("/import",response_class=HTMLResponse)
def page(request:Request):
    if not can_manage(request.state.user):return HTMLResponse("Forbidden",403)
    return request.app.state.templates.TemplateResponse(request=request,name="bulk/import.html",context={"request":request,"page_title":"Bulk Import","networks":list_networks(),"groups":list_policy_groups(),"result":None,"error":None,"batch":None})
@router.post("/import",response_class=HTMLResponse)
async def preview(request:Request,file:UploadFile=File(...),kind:str=Form(...),protocol:str=Form("HTTPS"),management_type:str=Form("custom"),category_slug:str=Form(""),scope_mode:str=Form("selected"),network_ids:list[int]=Form(default=[]),policy_group_ids:list[int]=Form(default=[]),reason:str=Form(...),change_reference:str=Form(""),csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    if management_type!="custom":return HTMLResponse("Bulk Import manages standalone custom ALLOW rules only. Application dependencies must be managed inside Application Policies.",400)
    if kind not in("domain","ip"):return HTMLResponse("Invalid import type",400)
    raw=await file.read(MAX_IMPORT_BYTES+1);error=None;result=None;batch=None
    try:
        if len(raw)>MAX_IMPORT_BYTES:raise ValueError("Import file is larger than 2 MB.")
        rows=_parse(raw.decode("utf-8-sig"))
        if len(rows)>MAX_IMPORT_ROWS:raise ValueError(f"Import limit is {MAX_IMPORT_ROWS} entries per batch.")
        nets,m=_maps();groups,gm=_group_map();accepted=[];rejected=[]
        for idx,row in enumerate(rows,1):
            dest=(row.get("destination") or "").strip();row_proto=(row.get("protocol") or protocol).strip().upper();row_reason=(row.get("reason") or reason).strip();row_ref=(row.get("change_reference") or change_reference).strip();row_exp=(row.get("expires_at") or "").strip();row_scope=(row.get("scope_mode") or scope_mode).strip().lower();ids,unknown=_scope((row.get("networks") or "").strip(),network_ids,m);gids,gunknown=_scope((row.get("access_profiles") or row.get("policy_groups") or "").strip(),policy_group_ids,gm)
            try:
                if not dest:raise ValueError("Missing destination")
                if row_proto not in("HTTP","HTTPS","BOTH"):raise ValueError("Invalid protocol")
                if row_scope not in("selected","all_proxy"):raise ValueError("Invalid scope mode")
                if row_scope=="selected" and not ids and not gids:raise ValueError("No network or Access Profile scope selected")
                if row_scope=="selected" and unknown:raise ValueError("Unknown network scope: "+", ".join(unknown))
                if row_scope=="selected" and gunknown:raise ValueError("Unknown Access Profile: "+", ".join(gunknown))
                nd=normalize_domain(dest) if kind=="domain" else normalize_ip(dest)
                if len(row_reason)<3:raise ValueError("A change reason is required")
                accepted.append({"row":idx,"destination":nd,"protocol":row_proto,"scope_mode":row_scope,"network_ids":ids if row_scope=="selected" else [],"policy_group_ids":gids if row_scope=="selected" else [],"reason":row_reason,"change_reference":row_ref,"expires_at":row_exp})
            except Exception as exc:rejected.append({"row":idx,"destination":dest,"error":str(exc)})
        defaults={"kind":kind,"management_type":management_type,"category_slug":category_slug,"scope_mode":scope_mode,"policy_group_ids":[int(x) for x in policy_group_ids]}
        exp=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat();c=connect()
        try:
            cur=c.execute("INSERT INTO import_batches(actor,kind,management_type,category_slug,defaults_json,rows_json,accepted_count,rejected_count,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",(u["username"],kind,management_type,category_slug or None,json.dumps(defaults),json.dumps({"accepted":accepted,"rejected":rejected}),len(accepted),len(rejected),exp));c.commit();batch=cur.lastrowid
        finally:c.close()
        result={"accepted":accepted,"rejected":rejected,"total":len(rows)};audit(u["username"],"BULK_PREVIEW","SUCCESS","batch",batch,auth.client_ip(request),json.dumps({"accepted":len(accepted),"rejected":len(rejected)}))
    except Exception as exc:error=str(exc)
    return request.app.state.templates.TemplateResponse(request=request,name="bulk/import.html",context={"request":request,"page_title":"Bulk Import","networks":list_networks(),"groups":list_policy_groups(),"result":result,"error":error,"batch":batch},status_code=400 if error else 200)
@router.post("/import/{batch_id}/apply")
def apply(batch_id:int,request:Request,csrf_token:str=Form(...)):
    u=request.state.user
    if not can_manage(u):return HTMLResponse("Forbidden",403)
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request",403)
    c=connect()
    try:r=c.execute("SELECT * FROM import_batches WHERE id=? AND status='preview'",(batch_id,)).fetchone()
    finally:c.close()
    if not r:return RedirectResponse("/bulk/import?error=Import+batch+not+found+or+already+used",303)
    exp=datetime.fromisoformat(r["expires_at"]);exp=exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc)>=exp:return RedirectResponse("/bulk/import?error=Import+preview+expired",303)
    payload=json.loads(r["rows_json"]);ok=0;errs=[]
    for row in payload.get("accepted",[]):
        try:create_rule(r["kind"],row["destination"],row["protocol"],row["network_ids"],u["username"],row["reason"],row.get("change_reference","") or "",row.get("expires_at","") or "",management_type=r["management_type"],category_slug=r["category_slug"],scope_mode=row.get("scope_mode","selected"),policy_group_ids=row.get("policy_group_ids") or []);ok+=1
        except Exception as exc:errs.append({"destination":row["destination"],"error":str(exc)})
    c=connect()
    try:c.execute("UPDATE import_batches SET status='applied' WHERE id=?",(batch_id,));c.commit()
    finally:c.close()
    audit(u["username"],"BULK_APPLY","SUCCESS" if not errs else "PARTIAL","batch",batch_id,auth.client_ip(request),json.dumps({"created":ok,"errors":errs[:20]}))
    return RedirectResponse("/bulk/import?msg="+f"{ok}+rules+created+as+pending+changes"+("&error=Some+rows+failed+during+apply" if errs else ""),303)
def _export(kind):
    output=io.StringIO();writer=csv.writer(output)
    writer.writerow(["action","destination","protocol","scope_mode","access_profiles","networks","status","reason","change_reference","expires_at"])
    for r in list_rules(kind,management="custom",include_deleted=False,standalone_only=True):
        profiles=";".join(g["name"] for g in r.get("policy_groups",[]))
        networks=";".join((f"VLAN{n['vlan_id']}" if n.get('vlan_id') else n['cidr']) for n in r.get("networks",[]))
        writer.writerow(["ALLOW",r["destination"],r["protocol"],r.get("scope_mode") or "selected",profiles,networks,r["status"],r.get("reason") or "",r.get("change_reference") or "",r.get("expires_at") or ""])
    return output.getvalue()
@router.get("/export/domains.csv")
def export_domains(request:Request):return Response(_export("domain"),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=allowed-domains.csv"})
@router.get("/export/ips.csv")
def export_ips(request:Request):return Response(_export("ip"),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=allowed-ips.csv"})
