import json
from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from app import auth
from app.db import audit
from app.services.rules import list_rules, list_networks, list_categories, get_rule, create_rule, update_rule, set_status
from app.services.apply import save_apply_state,apply_saved_change,apply_message

router = APIRouter(prefix="/rules")
BASE = "/rules/system"


def admin_only(request):
    return request.state.user and request.state.user["role"] == "admin"


def _apply_after_save(request,u,description,baseline_dirty):
    result=apply_saved_change(u["username"],auth.client_ip(request),description,preexisting_dirty=baseline_dirty,role=u["role"])
    return result,apply_message(result)


@router.get("/system", response_class=HTMLResponse)
def page(request: Request):
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="domains/system.html",
        context={
            "request": request,
            "page_title": "System Policies",
            "rules": list_rules("domain", "system"),
            "categories": list_categories(True),
        },
    )


@router.get("/system/add", response_class=HTMLResponse)
def add_page(request: Request):
    if not admin_only(request):
        return HTMLResponse("Forbidden", 403)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="domains/system_form.html",
        context={
            "request": request,
            "page_title": "Add System Policy Dependency",
            "rule": None,
            "networks": list_networks(),
            "categories": list_categories(True),
            "error": None,
        },
    )


@router.post("/system/add")
def add_submit(request: Request, destination: str = Form(...), protocol: str = Form(...), category_slug: str = Form(...),
               network_ids: list[int] = Form(...), reason: str = Form(...), change_reference: str = Form(""),
               expires_at: str = Form(""), csrf_token: str = Form(...)):
    u = request.state.user
    if not admin_only(request):
        return HTMLResponse("Forbidden", 403)
    if not auth.check_csrf(u, csrf_token):
        return HTMLResponse("Invalid request", 403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        result = create_rule("domain", destination, protocol, network_ids, u["username"], reason,
                             change_reference, expires_at, management_type="system", category_slug=category_slug)
        audit(u["username"], "SYSTEM_DOMAIN_CREATE", "SUCCESS", "rule", result["id"], auth.client_ip(request), json.dumps(result))
        applied,msg=_apply_after_save(request,u,"Save protected system rule "+destination,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE + "?"+key+"="+quote_plus(msg), 303)
    except Exception as exc:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="domains/system_form.html",
            context={"request": request, "page_title": "Add System Policy Dependency", "rule": None,
                     "networks": list_networks(), "categories": list_categories(True), "error": str(exc)},
            status_code=400,
        )


@router.get("/system/{rule_id}/edit", response_class=HTMLResponse)
def edit_page(rule_id: int, request: Request):
    if not admin_only(request):
        return HTMLResponse("Forbidden", 403)
    rule = get_rule(rule_id)
    if not rule or rule["management_type"] != "system":
        return HTMLResponse("Not found", 404)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="domains/system_form.html",
        context={"request": request, "page_title": "Edit System Policy Dependency", "rule": rule,
                 "networks": list_networks(), "categories": list_categories(True), "error": None},
    )


@router.post("/system/{rule_id}/edit")
def edit_submit(rule_id: int, request: Request, destination: str = Form(...), protocol: str = Form(...),
                category_slug: str = Form(...), network_ids: list[int] = Form(...), reason: str = Form(...),
                change_reference: str = Form(""), expires_at: str = Form(""), csrf_token: str = Form(...)):
    u = request.state.user
    if not admin_only(request):
        return HTMLResponse("Forbidden", 403)
    if not auth.check_csrf(u, csrf_token):
        return HTMLResponse("Invalid request", 403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        result = update_rule(rule_id, destination, protocol, network_ids, u["username"], reason,
                             change_reference, expires_at, allow_system=True, category_slug=category_slug)
        audit(u["username"], "SYSTEM_DOMAIN_EDIT", "SUCCESS", "rule", rule_id, auth.client_ip(request), json.dumps(result))
        applied,msg=_apply_after_save(request,u,"Save protected system rule "+destination,baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE + "?"+key+"="+quote_plus(msg), 303)
    except Exception as exc:
        return request.app.state.templates.TemplateResponse(
            request=request,
            name="domains/system_form.html",
            context={"request": request, "page_title": "Edit System Policy Dependency", "rule": get_rule(rule_id),
                     "networks": list_networks(), "categories": list_categories(True), "error": str(exc)},
            status_code=400,
        )


@router.post("/system/{rule_id}/status")
def status(rule_id: int, request: Request, status: str = Form(...), csrf_token: str = Form(...)):
    u = request.state.user
    if not admin_only(request):
        return HTMLResponse("Forbidden", 403)
    if not auth.check_csrf(u, csrf_token):
        return HTMLResponse("Invalid request", 403)
    try:
        baseline_dirty=save_apply_state()["dirty"]
        set_status(rule_id, status, u["username"], allow_system=True)
        audit(u["username"], "SYSTEM_DOMAIN_" + status.upper(), "SUCCESS", "rule", rule_id, auth.client_ip(request))
        applied,msg=_apply_after_save(request,u,"Update protected system rule",baseline_dirty)
        key="msg" if applied.get("ok") else "error"
        return RedirectResponse(BASE + "?"+key+"="+quote_plus(msg), 303)
    except Exception as exc:
        return RedirectResponse(BASE + "?error=" + str(exc).replace(" ", "+"), 303)
