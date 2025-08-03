import os
import signal
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from .models import Package

app = FastAPI()
# point templates to our package's templates/ dir
templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "templates")
)

# In-memory store
_packages: dict[str, Package] = {}

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Web UI: list & simple form."""
    return templates.TemplateResponse(
        "index.html", {"request": request, "packages": list(_packages.values())}
    )

@app.get("/api/packages", response_model=list[Package])
async def api_list_packages():
    return list(_packages.values())

@app.get("/api/packages/{name}", response_model=Package)
async def api_get_package(name: str):
    pkg = _packages.get(name)
    if not pkg:
        raise HTTPException(404, "Package not found")
    return pkg

@app.post("/api/packages", response_model=Package)
async def api_create_package(pkg: Package):
    _packages[pkg.name] = pkg
    return pkg

@app.post("/api/packages/form")
async def api_create_from_form(
    name: str = Form(...),
    version: str = Form(...),
    description: str = Form(...),
):
    pkg = Package(name=name, version=version, description=description)
    _packages[pkg.name] = pkg
    # redirect back to home so form stays on the web UI
    return RedirectResponse("/", status_code=303)
