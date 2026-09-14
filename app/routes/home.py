from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from app.core.config import resource_path, settings

router = APIRouter()
templates = Jinja2Templates(directory=resource_path("app/templates"))

@router.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "BlackRoute-Web | CyberNest Labs"}
    )

@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    icon_path = settings.STATIC_DIR / "CyberNestLabsLogo.png"
    if icon_path.exists():
        return FileResponse(icon_path, media_type="image/png")
    return Response(status_code=204)
