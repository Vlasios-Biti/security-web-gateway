from fastapi import APIRouter,Request
from fastapi.responses import HTMLResponse
from app.db import connect
router=APIRouter(prefix="/changes")
@router.get("/audit",response_class=HTMLResponse)
def page(request:Request):
    c=connect()
    try:rows=[dict(x) for x in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 300")]
    finally:c.close()
    return request.app.state.templates.TemplateResponse(request=request,name="audit/list.html",
        context={"request":request,"page_title":"Audit Log","rows":rows})
