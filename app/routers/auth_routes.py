from fastapi import APIRouter,Request,Form
from fastapi.responses import HTMLResponse,RedirectResponse
from app import auth
from app.config import SESSION_COOKIE
router=APIRouter()
@router.get("/login",response_class=HTMLResponse)
def login_page(request:Request):
    if request.state.user:return RedirectResponse("/",303)
    return request.app.state.templates.TemplateResponse(request=request,name="login.html",context={"request":request,"error":None})
@router.post("/login")
def login_submit(request:Request,username:str=Form(...),password:str=Form(...)):
    user=auth.authenticate(username,password,request)
    if not user:
        return request.app.state.templates.TemplateResponse(request=request,name="login.html",
            context={"request":request,"error":"Invalid username or password."},status_code=401)
    token=auth.create_session(user["id"],request);resp=RedirectResponse("/",303)
    resp.set_cookie(SESSION_COOKIE,token,max_age=8*3600,httponly=True,secure=True,samesite="strict",path="/")
    return resp
@router.post("/logout")
def logout(request:Request,csrf_token:str=Form(...)):
    u=request.state.user
    if not auth.check_csrf(u,csrf_token):return HTMLResponse("Invalid request.",403)
    auth.revoke_current_session(request,u);resp=RedirectResponse("/login",303);resp.delete_cookie(SESSION_COOKIE,path="/");return resp
