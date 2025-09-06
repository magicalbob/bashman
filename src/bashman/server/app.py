import re
import os
import time
import json
import hashlib
from base64 import b64decode
from email.utils import parsedate_to_datetime
from datetime import timezone
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import (
    FastAPI,
    File,
    UploadFile,
    Form,
    HTTPException,
    Depends,
    Response,
    Request,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sqlite3 import IntegrityError as SQLiteIntegrityError
try:
    from aiosqlite import IntegrityError as AIOSQLiteIntegrityError  # type: ignore
except Exception:  # pragma: no cover
    AIOSQLiteIntegrityError = SQLiteIntegrityError  # type: ignore

# Crypto is optional; only required if auth enforcement is enabled
try:
    from cryptography.hazmat.primitives.serialization import load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives import hashes as _hashes
except Exception:  # pragma: no cover
    load_ssh_public_key = None  # type: ignore

from .database.factory import DatabaseFactory
from .database.base import DatabaseInterface
from .models import PackageMetadata, PackageStatus

# -----------------------
# Global DB & app setup
# -----------------------

db: Optional[DatabaseInterface] = None

DB_PATH = os.environ.get("BASHMAN_DB_PATH", "bashman.db")
REQUIRE_AUTH = os.environ.get("BASHMAN_REQUIRE_AUTH", "0") == "1"
MAX_SKEW_SECONDS = 300  # 5 minutes for clock skew & nonce window
_NONCE_CACHE: dict[tuple[str, str], float] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management (init/close DB)."""
    global db
    db = await DatabaseFactory.create_and_initialize("sqlite", db_path=DB_PATH)
    try:
        yield
    finally:
        if db:
            await db.close()

app = FastAPI(
    title="Bashman Registry",
    description="Package manager for Bash scripts",
    version="0.1.0",
    lifespan=lifespan,
)

# -----------------------
# Helpers
# -----------------------

# Shell validation regex
SHELL_REGEX = re.compile(r"^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)")

def get_database() -> DatabaseInterface:
    """Dependency injection for database."""
    if db is None:
        raise HTTPException(500, "Database not initialized")
    return db

def validate_shell_script(content: bytes) -> None:
    """Validate that content is a shell script with proper shebang."""
    if not content:
        raise HTTPException(400, "Script content cannot be empty")
    first_line = content.splitlines()[0].decode(errors="ignore") if content else ""
    if not SHELL_REGEX.match(first_line):
        raise HTTPException(
            400,
            detail=(
                "Script must begin with a recognized shell shebang, "
                "e.g. #!/bin/bash or #!/usr/bin/env bash"
            ),
        )

# ---- Signature verification helpers (optional) ----

async def _fetch_user_public_key(database: DatabaseInterface, nickname: str) -> Optional[str]:
    """
    Get the user's public key by nickname.
    This reaches into the SQLite implementation to avoid changing the interface.
    """
    try:
        from .database.sqlite import SQLiteDatabase  # type: ignore
        if isinstance(database, SQLiteDatabase) and getattr(database, "_db", None):
            cur = await database._db.execute(
                "SELECT public_key FROM users WHERE nickname = ?", (nickname,)
            )
            row = await cur.fetchone()
            return row[0] if row else None
    except Exception:
        return None
    return None

def _parse_alg(alg: str) -> Optional[str]:
    if alg == "ed25519":
        return "ed25519"
    if alg == "rsa-pss-sha256":
        return "rsa"
    if alg == "ecdsa-sha256":
        return "ecdsa"
    return None

def _canonical_bytes(method: str, path_qs: str, date_str: str, nonce: str, body_sha256_hex: str) -> bytes:
    # METHOD \n PATH?QUERY \n RFC1123_DATE \n NONCE \n SHA256_HEX
    return f"{method.upper()}\n{path_qs}\n{date_str}\n{nonce}\n{body_sha256_hex}".encode("utf-8")

def _within_skew(date_str: str) -> bool:
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return abs((time.time() - dt.timestamp())) <= MAX_SKEW_SECONDS
    except Exception:
        return False

def _replay_ok(user: str, nonce: str) -> bool:
    now = time.time()
    # prune stale entries
    for (u, n), ts in list(_NONCE_CACHE.items()):
        if now - ts > MAX_SKEW_SECONDS:
            _NONCE_CACHE.pop((u, n), None)
    key = (user, nonce)
    if key in _NONCE_CACHE:
        return False
    _NONCE_CACHE[key] = now
    return True

async def _verify_signature_or_401(request: Request, database: DatabaseInterface, content: bytes | None) -> None:
    """
    Verify Bashman signature if present; if REQUIRE_AUTH is on, enforce presence and validity.
    """
    user = request.headers.get("X-Bashman-User")
    date_str = request.headers.get("X-Bashman-Date")
    nonce = request.headers.get("X-Bashman-Nonce")
    alg = request.headers.get("X-Bashman-Alg")
    auth = request.headers.get("Authorization", "")

    if not (user and date_str and nonce and auth.startswith("Bashman ")):
        if REQUIRE_AUTH:
            raise HTTPException(401, "Missing Bashman signature headers")
        return

    if not _within_skew(date_str):
        raise HTTPException(401, "Signature date outside allowed skew")

    if not _replay_ok(user, nonce):
        raise HTTPException(401, "Replay detected")

    algo = _parse_alg(alg or "")
    if load_ssh_public_key is None and REQUIRE_AUTH:
        raise HTTPException(500, "Server missing crypto support")

    pubkey_text = await _fetch_user_public_key(database, user)
    if pubkey_text is None:
        if REQUIRE_AUTH:
            raise HTTPException(401, "Unknown user")
        return

    try:
        pub = load_ssh_public_key(pubkey_text.encode("utf-8"))  # type: ignore
        parts = request.url
        path_qs = parts.path + (("?" + parts.query) if parts.query else "")
        body = content or b""
        body_hex = hashlib.sha256(body).hexdigest()
        msg = _canonical_bytes(request.method, path_qs, date_str, nonce, body_hex)
        sig = b64decode(auth.split(" ", 1)[1].strip())

        if isinstance(pub, ed25519.Ed25519PublicKey):
            if algo != "ed25519" and REQUIRE_AUTH:
                raise HTTPException(401, "Algorithm mismatch")
            pub.verify(sig, msg)  # type: ignore
        elif isinstance(pub, rsa.RSAPublicKey):
            if algo != "rsa" and REQUIRE_AUTH:
                raise HTTPException(401, "Algorithm mismatch")
            pub.verify(  # type: ignore
                sig,
                msg,
                _padding.PSS(mgf=_padding.MGF1(_hashes.SHA256()), salt_length=_padding.PSS.MAX_LENGTH),
                _hashes.SHA256(),
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if algo != "ecdsa" and REQUIRE_AUTH:
                raise HTTPException(401, "Algorithm mismatch")
            pub.verify(sig, msg, ec.ECDSA(_hashes.SHA256()))  # type: ignore
        else:
            if REQUIRE_AUTH:
                raise HTTPException(401, "Unsupported public key type")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Signature verification failed")


async def require_auth(request: Request):
    if not REQUIRE_AUTH:
        return
    # allow bootstrap/health without auth
    path = request.url.path
    if path.startswith("/api/users") or path == "/health":
        return
    user = request.headers.get("X-Bashman-User")
    auth = request.headers.get("Authorization", "")
    if not user or not auth.startswith("Bashman "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bashman auth headers")


# -----------------------
# Legacy endpoints (back-compat)
# -----------------------

@app.get("/scripts", deprecated=True)
async def list_scripts_legacy(
    _auth: None = Depends(require_auth),
    database: DatabaseInterface = Depends(get_database),
):
    packages = await database.list_packages(status="quarantined", limit=1000)
    return JSONResponse(content=[pkg.name for pkg in packages])

@app.post("/scripts", deprecated=True)
async def upload_script_legacy(
    file: UploadFile = File(...),
    _auth: None = Depends(require_auth),
    database: DatabaseInterface = Depends(get_database),
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
        status=PackageStatus.QUARANTINED,
    )
    await database.create_package(package_metadata, content)
    return {"status": "quarantined", "filename": file.filename}

# -----------------------
# New API endpoints
# -----------------------

@app.get("/api/packages", response_model=List[PackageMetadata])
async def list_packages(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = "published",
    database: DatabaseInterface = Depends(get_database),
):
    packages = await database.list_packages(limit, offset, status)
    return packages

@app.get("/api/packages/{name}", response_model=PackageMetadata)
async def get_package(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database),
):
    package = await database.get_package(name, version)
    if not package:
        raise HTTPException(404, f"Package {name} not found")
    return package

@app.get("/api/packages/{name}/download")
async def download_package(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database),
):
    result = await database.get_package_with_content(name, version)
    if not result:
        raise HTTPException(404, f"Package {name} not found")
    package, content = result

    if package.status != PackageStatus.PUBLISHED:
        raise HTTPException(403, f"Package {name} is not published")

    await database.record_download(package.id)  # type: ignore[arg-type]

    filename = f"{package.name}-{package.version}"
    return Response(
        content=content,
        media_type="application/x-shellscript",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(content)),
        },
    )

@app.get("/api/packages/{name}/versions", response_model=List[str])
async def get_package_versions(
    name: str,
    database: DatabaseInterface = Depends(get_database),
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
    keywords: str                = Form("[]"),
    dependencies: str            = Form("{}"),
    platforms: str               = Form("[]"),
    shell_version: Optional[str] = Form(None),
    file: UploadFile             = File(...),
    database: DatabaseInterface  = Depends(get_database),
):
    """Create a new package with full metadata (via multipart form)."""
    content = await file.read()
    validate_shell_script(content)

    # Parse JSON-encoded form fields
    try:
        kw_list = json.loads(keywords)
        dep_map = json.loads(dependencies)
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
        status=PackageStatus.QUARANTINED,
    )
    pkg_id = await database.create_package(pkg, content)

    return {
        "id": pkg_id,
        "status": "created",
        "message": f"Package {name} version {version} created successfully",
    }

@app.get("/api/search", response_model=List[PackageMetadata])
async def search_packages(
    q: str,
    limit: int = 50,
    database: DatabaseInterface = Depends(get_database),
):
    if not q.strip():
        raise HTTPException(400, "Search query cannot be empty")
    results = await database.search_packages(q.strip(), limit)
    return results

@app.get("/api/trending", response_model=List[PackageMetadata])
async def get_trending_packages(
    days: int = 7,
    limit: int = 10,
    database: DatabaseInterface = Depends(get_database),
):
    return await database.get_trending_packages(days, limit)

@app.get("/api/stats")
async def get_stats(database: DatabaseInterface = Depends(get_database)):
    package_count = await database.get_package_count()
    return {
        "total_packages": package_count,
        "storage_type": "database",
        "status": "operational",
    }

@app.post("/api/packages/{name}/{version}/publish")
async def publish_package(
    name: str,
    version: str,
    database: DatabaseInterface = Depends(get_database),
):
    success = await database.update_package(name, version, {"status": PackageStatus.PUBLISHED})
    if not success:
        raise HTTPException(404, f"Package {name} version {version} not found")
    return {"status": "published", "message": f"Package {name} version {version} is now published"}

@app.delete("/api/packages/{name}/{version}")
async def delete_package(
    name: str,
    version: str,
    database: DatabaseInterface = Depends(get_database),
):
    success = await database.delete_package(name, version)
    if not success:
        raise HTTPException(404, f"Package {name} version {version} not found")
    return {"status": "deleted", "message": f"Package {name} version {version} has been deleted"}

@app.get("/api/packages/{name}/content", deprecated=True)
async def get_package_content_debug(
    name: str,
    version: Optional[str] = None,
    database: DatabaseInterface = Depends(get_database),
):
    content = await database.get_package_content(name, version)
    if not content:
        raise HTTPException(404, f"Package {name} not found")
    return Response(content=content, media_type="text/plain")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "storage": "database-only"}

# -----------------------
# User registration
# -----------------------

class UserCreate(BaseModel):
    nickname: str
    public_key: str

@app.post("/api/users", status_code=201)
async def create_user(user: UserCreate, database: DatabaseInterface = Depends(get_database)):
    try:
        await database.store_user_info(user.nickname, user.public_key)
        return {"status": "success", "message": "User registered successfully."}
    except (SQLiteIntegrityError, AIOSQLiteIntegrityError):
        raise HTTPException(status_code=409, detail="User with this nickname or key already exists.")
