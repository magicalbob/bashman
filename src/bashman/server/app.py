import re
import os
import hashlib
import json
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Response
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import List, Optional

from .database.factory import DatabaseFactory
from .database.base import DatabaseInterface
from .models import PackageMetadata, PackageStatus

# Global database instance
db: Optional[DatabaseInterface] = None

# Get database path from environment or default
DB_PATH = os.environ.get('BASHMAN_DB_PATH', 'bashman.db')

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global db
    db = await DatabaseFactory.create_and_initialize("sqlite", db_path=DB_PATH)
    yield
    if db:
        await db.close()

app = FastAPI(
    title="Bashman Registry",
    description="Package manager for Bash scripts",
    version="0.1.0",
    lifespan=lifespan
)

# Shell validation regex
SHELL_REGEX = re.compile(r'^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)')

def get_database() -> DatabaseInterface:
    """Dependency injection for database"""
    if db is None:
        raise HTTPException(500, "Database not initialized")
    return db

def validate_shell_script(content: bytes) -> None:
    """Validate that content is a shell script with proper shebang"""
    if not content:
        raise HTTPException(400, "Script content cannot be empty")
    first_line = content.splitlines()[0].decode(errors="ignore") if content else ""
    if not SHELL_REGEX.match(first_line):
        raise HTTPException(
            400,
            detail=(
                "Script must begin with a recognized shell shebang, "
                "e.g. #!/bin/bash or #!/usr/bin/env bash"
            )
        )

#
# Legacy endpoints for backward compatibility
#

@app.get("/scripts", deprecated=True)
async def list_scripts_legacy(database: DatabaseInterface = Depends(get_database)):
    packages = await database.list_packages(status="quarantined", limit=1000)
    return JSONResponse(content=[pkg.name for pkg in packages])

@app.post("/scripts", deprecated=True)
async def upload_script_legacy(
    file: UploadFile = File(...),
    database: DatabaseInterface = Depends(get_database)
):
    content = await file.read()
    validate_shell_script(content)

    existing = await database.get_package(file.filename)
    if existing:
        raise HTTPException(409, f"{file.filename} already exists")

    package_metadata = PackageMetadata(
        name=file.filename,
        version="0.1.0",
        description=f"Uploaded script: {file.filename}",
        file_size=len(content),
        file_hash=hashlib.sha256(content).hexdigest(),
        status=PackageStatus.QUARANTINED
    )
    await database.create_package(package_metadata, content)

    return {"status": "quarantined", "filename": file.filename}

#
# New API endpoints
#

@app.get("/api/packages", response_model=List[PackageMetadata])
async def list_packages(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = "published",
    database: DatabaseInterface = Depends(get_database)
):
    packages = await database.list_packages(limit, offset, status)
    return packages

@app.get("/api/packages/{name}", response_model=PackageMetadata)
async def get_package(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database)
):
    package = await database.get_package(name, version)
    if not package:
        raise HTTPException(404, f"Package {name} not found")
    return package

@app.get("/api/packages/{name}/download")
async def download_package(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database)
):
    result = await database.get_package_with_content(name, version)
    if not result:
        raise HTTPException(404, f"Package {name} not found")
    package, content = result

    if package.status != PackageStatus.PUBLISHED:
        raise HTTPException(403, f"Package {name} is not published")

    await database.record_download(package.id)

    filename = f"{package.name}-{package.version}"
    return Response(
        content=content,
        media_type="application/x-shellscript",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(content))
        }
    )

@app.get("/api/packages/{name}/versions", response_model=List[str])
async def get_package_versions(
    name: str,
    database: DatabaseInterface = Depends(get_database)
):
    versions = await database.get_package_versions(name)
    if not versions:
        raise HTTPException(404, f"Package {name} not found")
    return versions

@app.post("/api/packages", response_model=dict)
async def create_package(
    name: str                    = Form(...),
    version: str                 = Form(...),
    description: str             = Form(...),
    author: Optional[str]        = Form(None),
    homepage: Optional[str]      = Form(None),
    repository: Optional[str]    = Form(None),
    license: Optional[str]       = Form(None),
    keywords: str                = Form('[]'),
    dependencies: str            = Form('{}'),
    platforms: str               = Form('[]'),
    shell_version: Optional[str] = Form(None),
    file: UploadFile             = File(...),
    database: DatabaseInterface  = Depends(get_database),
):
    """Create a new package with full metadata (via multipart form)."""
    content = await file.read()
    validate_shell_script(content)

    # Parse JSON-encoded form fields
    try:
        kw_list   = json.loads(keywords)
        dep_map   = json.loads(dependencies)
        plat_list = json.loads(platforms)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON in keywords/dependencies/platforms")

    existing = await database.get_package(name, version)
    if existing:
        raise HTTPException(409, f"Package {name} version {version} already exists")

    pkg = PackageMetadata(
        name=name,
        version=version,
        description=description,
        author=author,
        homepage=homepage,
        repository=repository,
        license=license,
        keywords=kw_list,
        dependencies=dep_map,
        platforms=plat_list,
        shell_version=shell_version,
        file_size=len(content),
        file_hash=hashlib.sha256(content).hexdigest(),
        status=PackageStatus.QUARANTINED
    )
    pkg_id = await database.create_package(pkg, content)

    return {
        "id": pkg_id,
        "status": "created",
        "message": f"Package {name} version {version} created successfully"
    }

@app.get("/api/search", response_model=List[PackageMetadata])
async def search_packages(
    q: str,
    limit: int = 50,
    database: DatabaseInterface = Depends(get_database)
):
    if not q.strip():
        raise HTTPException(400, "Search query cannot be empty")
    results = await database.search_packages(q.strip(), limit)
    return results

@app.get("/api/trending", response_model=List[PackageMetadata])
async def get_trending_packages(
    days: int = 7,
    limit: int = 10,
    database: DatabaseInterface = Depends(get_database)
):
    return await database.get_trending_packages(days, limit)

@app.get("/api/stats")
async def get_stats(database: DatabaseInterface = Depends(get_database)):
    package_count = await database.get_package_count()
    return {
        "total_packages": package_count,
        "storage_type": "database",
        "status": "operational"
    }

@app.post("/api/packages/{name}/{version}/publish")
async def publish_package(
    name: str,
    version: str,
    database: DatabaseInterface = Depends(get_database)
):
    success = await database.update_package(
        name, version, {"status": PackageStatus.PUBLISHED}
    )
    if not success:
        raise HTTPException(404, f"Package {name} version {version} not found")
    return {"status": "published", "message": f"Package {name} version {version} is now published"}

@app.delete("/api/packages/{name}/{version}")
async def delete_package(
    name: str,
    version: str,
    database: DatabaseInterface = Depends(get_database)
):
    success = await database.delete_package(name, version)
    if not success:
        raise HTTPException(404, f"Package {name} version {version} not found")
    return {"status": "deleted", "message": f"Package {name} version {version} has been deleted"}

@app.get("/api/packages/{name}/content", deprecated=True)
async def get_package_content_debug(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database)
):
    content = await database.get_package_content(name, version)
    if not content:
        raise HTTPException(404, f"Package {name} not found")
    return Response(content=content, media_type="text/plain")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "storage": "database-only"}
