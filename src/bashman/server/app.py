import os
import re
import hashlib
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import List, Optional

from .database.factory import DatabaseFactory
from .database.base import DatabaseInterface
from .models import PackageMetadata, CreatePackageRequest, PackageStatus

# Global database instance
db: Optional[DatabaseInterface] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global db
    # Startup
    db = await DatabaseFactory.create_and_initialize("sqlite", db_path="bashman.db")
    yield
    # Shutdown
    if db:
        await db.close()

app = FastAPI(lifespan=lifespan)

QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Allow absolute paths ending in sh|bash|zsh|csh|ksh|dash|fish, 
# plus the /usr/bin/env trick
SHELL_REGEX = re.compile(
    r"^#!\s*(?:/[^ \t]+/)*(?:env\s+)?(sh|bash|zsh|csh|ksh|dash|fish)\b"
)

def get_database() -> DatabaseInterface:
    """Dependency injection for database"""
    if db is None:
        raise HTTPException(500, "Database not initialized")
    return db

def calculate_file_hash(content: bytes) -> str:
    """Calculate SHA256 hash of file content"""
    return hashlib.sha256(content).hexdigest()

# Legacy endpoints for backward compatibility
@app.get("/scripts")
async def list_scripts():
    """Legacy endpoint - list quarantined scripts from filesystem"""
    valid = []
    for fname in os.listdir(QUARANTINE_DIR):
        path = os.path.join(QUARANTINE_DIR, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            first = f.readline().decode(errors="ignore")
        if SHELL_REGEX.match(first):
            valid.append(fname)
    return JSONResponse(content=valid)

@app.post("/scripts")
async def upload_script(file: UploadFile = File(...), database: DatabaseInterface = Depends(get_database)):
    """Legacy endpoint - upload script with basic metadata extraction"""
    content = await file.read()
    first_line = content.splitlines()[0].decode(errors="ignore") if content else ""
    
    if not SHELL_REGEX.match(first_line):
        raise HTTPException(
            400,
            detail=(
                "Script must begin with a recognized shell shebang, "
                "e.g. #!/bin/bash or #!/usr/bin/env bash"
            )
        )

    # Check if file already exists in database
    existing = await database.get_package(file.filename)
    if existing:
        raise HTTPException(409, f"{file.filename} already exists")
    
    # Save file
    dest = os.path.join(QUARANTINE_DIR, file.filename)
    if os.path.exists(dest):
        raise HTTPException(409, f"{file.filename} already exists in filesystem")
    
    with open(dest, "wb") as out:
        out.write(content)
    
    # Create database entry
    package_metadata = PackageMetadata(
        name=file.filename,
        version="0.1.0",  # Default version for legacy uploads
        description=f"Uploaded script: {file.filename}",
        file_path=dest,
        file_size=len(content),
        file_hash=calculate_file_hash(content),
        status=PackageStatus.QUARANTINED
    )
    
    await database.create_package(package_metadata)
    
    return {"status": "quarantined", "filename": file.filename}

# New API endpoints
@app.get("/api/packages", response_model=List[PackageMetadata])
async def list_packages(
    limit: int = 100, 
    offset: int = 0,
    status: str = "published",
    database: DatabaseInterface = Depends(get_database)
):
    """List packages with pagination and filtering"""
    if status == "all":
        packages = await database.list_packages(limit, offset)
    else:
        # For now, just return published packages
        # TODO: Add status filtering to database interface
        packages = await database.list_packages(limit, offset)
        packages = [p for p in packages if p.status == status]
    
    return packages

@app.get("/api/packages/{name}", response_model=PackageMetadata)
async def get_package(
    name: str, 
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database)
):
    """Get a specific package"""
    package = await database.get_package(name, version)
    if not package:
        raise HTTPException(404, f"Package {name} not found")
    return package

@app.get("/api/packages/{name}/versions", response_model=List[str])
async def get_package_versions(
    name: str,
    database: DatabaseInterface = Depends(get_database)
):
    """Get all versions of a package"""
    versions = await database.get_package_versions(name)
    if not versions:
        raise HTTPException(404, f"Package {name} not found")
    return versions

@app.post("/api/packages", response_model=dict)
async def create_package(
    request: CreatePackageRequest,
    file: UploadFile = File(...),
    database: DatabaseInterface = Depends(get_database)
):
    """Create a new package with full metadata"""
    content = await file.read()
    first_line = content.splitlines()[0].decode(errors="ignore") if content else ""
    
    if not SHELL_REGEX.match(first_line):
        raise HTTPException(
            400,
            detail="Script must begin with a recognized shell shebang"
        )
    
    # Check for existing package
    existing = await database.get_package(request.name, request.version)
    if existing:
        raise HTTPException(409, f"Package {request.name} version {request.version} already exists")
    
    # Save file with proper naming
    filename = f"{request.name}-{request.version}"
    dest = os.path.join(QUARANTINE_DIR, filename)
    
    with open(dest, "wb") as out:
        out.write(content)
    
    # Create package metadata
    package_metadata = PackageMetadata(
        name=request.name,
        version=request.version,
        description=request.description,
        author=request.author,
        homepage=request.homepage,
        repository=request.repository,
        license=request.license,
        keywords=request.keywords,
        dependencies=request.dependencies,
        platforms=request.platforms,
        shell_version=request.shell_version,
        file_path=dest,
        file_size=len(content),
        file_hash=calculate_file_hash(content),
        status=PackageStatus.QUARANTINED
    )
    
    package_id = await database.create_package(package_metadata)
    
    return {
        "id": package_id,
        "status": "created",
        "message": f"Package {request.name} version {request.version} created successfully"
    }

@app.get("/api/search", response_model=List[PackageMetadata])
async def search_packages(
    q: str,
    limit: int = 50,
    database: DatabaseInterface = Depends(get_database)
):
    """Search packages"""
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
    """Get trending packages"""
    return await database.get_trending_packages(days, limit)

@app.get("/api/stats")
async def get_stats(database: DatabaseInterface = Depends(get_database)):
    """Get registry statistics"""
    package_count = await database.get_package_count()
    return {
        "total_packages": package_count,
        "status": "operational"
    }

@app.post("/api/packages/{name}/{version}/publish")
async def publish_package(
    name: str,
    version: str,
    database: DatabaseInterface = Depends(get_database)
):
    """Publish a quarantined package"""
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
    """Delete a package version"""
    success = await database.delete_package(name, version)
    
    if not success:
        raise HTTPException(404, f"Package {name} version {version} not found")
    
    return {"status": "deleted", "message": f"Package {name} version {version} has been deleted"}
