import re
import os
import time
import json
import hashlib
import asyncio
from base64 import b64decode
from email.utils import parsedate_to_datetime
from datetime import timezone
from contextlib import suppress, asynccontextmanager
from typing import Any, List, Optional, NamedTuple, Tuple

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
# Constants
# -----------------------
DB_PATH = os.environ.get("BASHMAN_DB_PATH", "bashman.db")
REQUIRE_AUTH = os.environ.get("BASHMAN_REQUIRE_AUTH", "0") == "1"
MAX_SKEW_SECONDS = 300  # 5 minutes for clock skew & nonce window
ALGORITHM_MISMATCH = "Algorithm mismatch"
AUTO_PUBLISH = os.environ.get("BASHMAN_AUTO_PUBLISH", "0") == "1"

# -----------------------
# Data structures for auth
# -----------------------
class SignatureData(NamedTuple):
    user: str
    date_str: str
    nonce: str
    algorithm: str
    signature: bytes
    message: bytes

# -----------------------
# Global variables
# -----------------------
db: Optional[DatabaseInterface] = None
_NONCE_CACHE: dict[tuple[str, str], float] = {}
_PUBLISHER_TASK: Optional[asyncio.Task] = None
_STOP_EVENT: Optional[asyncio.Event] = None

# -----------------------
# Shell validation
# -----------------------
SHELL_REGEX = re.compile(r"^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)")

# -----------------------
# Authentication helpers (refactored)
# -----------------------

def _extract_signature_headers(request: Request) -> Optional[tuple[str, str, str, str, str]]:
    """Extract signature headers from request. Returns None if any required header is missing."""
    user = request.headers.get("X-Bashman-User")
    date_str = request.headers.get("X-Bashman-Date")
    nonce = request.headers.get("X-Bashman-Nonce")
    alg = request.headers.get("X-Bashman-Alg")
    auth = request.headers.get("Authorization", "")

    if not (user and date_str and nonce and auth.startswith("Bashman ")):
        return None

    return user, date_str, nonce, alg or "", auth

def _validate_signature_timing(date_str: str, user: str, nonce: str) -> None:
    """Validate signature timing and prevent replay attacks."""
    if not _within_skew(date_str):
        raise HTTPException(401, "Signature date outside allowed skew")

    if not _replay_ok(user, nonce):
        raise HTTPException(401, "Replay detected")

def _prepare_signature_data(request: Request, user: str, date_str: str, nonce: str,
                          alg: str, auth: str, content: bytes | None) -> SignatureData:
    """Prepare signature data for verification."""
    parts = request.url
    path_qs = parts.path + (("?" + parts.query) if parts.query else "")
    body = content or b""
    body_hex = hashlib.sha256(body).hexdigest()
    msg = _canonical_bytes(request.method, path_qs, date_str, nonce, body_hex)
    sig = b64decode(auth.split(" ", 1)[1].strip())
    algorithm = _parse_alg(alg) or ""

    return SignatureData(user, date_str, nonce, algorithm, sig, msg)

def _verify_ed25519_signature(pub: ed25519.Ed25519PublicKey, sig_data: SignatureData) -> None:
    """Verify Ed25519 signature."""
    if sig_data.algorithm != "ed25519" and REQUIRE_AUTH:
        raise HTTPException(401, ALGORITHM_MISMATCH)
    pub.verify(sig_data.signature, sig_data.message)  # type: ignore

def _verify_rsa_signature(pub: rsa.RSAPublicKey, sig_data: SignatureData) -> None:
    """Verify RSA signature."""
    if sig_data.algorithm != "rsa" and REQUIRE_AUTH:
        raise HTTPException(401, ALGORITHM_MISMATCH)
    pub.verify(  # type: ignore
        sig_data.signature,
        sig_data.message,
        _padding.PSS(mgf=_padding.MGF1(_hashes.SHA256()), salt_length=_padding.PSS.MAX_LENGTH),
        _hashes.SHA256(),
    )

def _verify_ecdsa_signature(pub: ec.EllipticCurvePublicKey, sig_data: SignatureData) -> None:
    """Verify ECDSA signature."""
    if sig_data.algorithm != "ecdsa" and REQUIRE_AUTH:
        raise HTTPException(401, ALGORITHM_MISMATCH)
    pub.verify(sig_data.signature, sig_data.message, ec.ECDSA(_hashes.SHA256()))  # type: ignore

def _perform_signature_verification(public_key: object, sig_data: SignatureData) -> None:
    """Perform signature verification based on key type."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        _verify_ed25519_signature(public_key, sig_data)
    elif isinstance(public_key, rsa.RSAPublicKey):
        _verify_rsa_signature(public_key, sig_data)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        _verify_ecdsa_signature(public_key, sig_data)
    else:
        if REQUIRE_AUTH:
            raise HTTPException(401, "Unsupported public key type")

async def _verify_signature_or_401(request: Request, database: DatabaseInterface, content: bytes | None) -> None:
    """
    Verify Bashman signature if present; if REQUIRE_AUTH is on, enforce presence and validity.
    Refactored to reduce cognitive complexity.
    """
    # Extract headers
    header_data = _extract_signature_headers(request)
    if not header_data:
        if REQUIRE_AUTH:
            raise HTTPException(401, "Missing Bashman signature headers")
        return

    user, date_str, nonce, alg, auth = header_data

    # Validate timing and prevent replays
    _validate_signature_timing(date_str, user, nonce)

    # Check crypto support
    if load_ssh_public_key is None and REQUIRE_AUTH:
        raise HTTPException(500, "Server missing crypto support")

    # Get user's public key
    pubkey_text = await _fetch_user_public_key(database, user)
    if pubkey_text is None:
        if REQUIRE_AUTH:
            raise HTTPException(401, "Unknown user")
        return

    try:
        # Load public key and prepare signature data
        public_key = load_ssh_public_key(pubkey_text.encode("utf-8"))  # type: ignore
        sig_data = _prepare_signature_data(request, user, date_str, nonce, alg, auth, content)

        # Perform verification
        _perform_signature_verification(public_key, sig_data)

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Signature verification failed")

# -----------------------
# Existing helper functions (unchanged)
# -----------------------

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


async def _enqueue_publish_job(database: DatabaseInterface, pkg_id: int, name: str, version: str) -> None:
    """Best-effort enqueue using SQLiteDatabase internals; ignore if not available."""
    try:
        from .database.sqlite import SQLiteDatabase  # type: ignore
        if isinstance(database, SQLiteDatabase):
            await database.enqueue_publish(int(pkg_id), name, version)  # type: ignore[attr-defined]
    except Exception:
        # non-fatal
        pass

def _supports_publish_jobs(db: Any) -> bool:
    """Duck-typed capability check; avoids import/instance checks."""
    required = (
        "claim_next_publish_job",
        "complete_publish_job",
        "fail_publish_job",
        "update_package",
    )
    return all(hasattr(db, name) for name in required)

async def _safe_fail_job(database: Any, job_id: Any, msg: str) -> None:
    """Best-effort failure recording; swallow secondary errors."""
    with suppress(Exception):
        await database.fail_publish_job(job_id, msg)  # type: ignore[attr-defined]

async def _publisher_loop(database: DatabaseInterface, stop_event: asyncio.Event):
    """Background loop: claim pending jobs and publish them automatically."""
    # Guard quickly by capability rather than importing SQLiteDatabase
    if not _supports_publish_jobs(database):
        return

    async def _wait_for_stop(timeout: float = 1.0) -> None:
        """Sleep a bit, but wake promptly on shutdown."""
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    async def _claim_job() -> Optional[Tuple[Any, ...]]:
        """Try to claim the next job; return None on any error or no job."""
        try:
            return await database.claim_next_publish_job()  # type: ignore[attr-defined]
        except Exception:
            return None

    async def _process_job(job: Tuple[Any, ...]) -> None:
        """Publish the package for a claimed job, handling all failure paths."""
        job_id, _pkg_id, name, version, _attempts = job
        try:
            ok = await database.update_package(name, version, {"status": PackageStatus.PUBLISHED})
            if ok:
                await database.complete_publish_job(job_id)  # type: ignore[attr-defined]
            else:
                # Package/version not found; record as failed
                await database.fail_publish_job(job_id, "Package/version not found")  # type: ignore[attr-defined]
        except Exception as e:
            # Best-effort failure record; swallow secondary errors
            try:
                await database.fail_publish_job(job_id, str(e))  # type: ignore[attr-defined]
            except Exception:
                pass

    # Main loop: poll, process, or briefly wait
    while not stop_event.is_set():
        job = await _claim_job()
        if not job:
            await _wait_for_stop(1.0)
            continue
        await _process_job(job)

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

# -----------------------
# Global DB & app setup
# -----------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management (init/close DB)."""
    global db
    global _PUBLISHER_TASK, _STOP_EVENT
    db = await DatabaseFactory.create_and_initialize("sqlite", db_path=DB_PATH)
    # Start background publisher if enabled
    if AUTO_PUBLISH and db is not None:
        _STOP_EVENT = asyncio.Event()
        _PUBLISHER_TASK = asyncio.create_task(_publisher_loop(db, _STOP_EVENT))
    try:
        yield
    finally:
        # Stop background publisher
        if _STOP_EVENT is not None:
            _STOP_EVENT.set()
        if _PUBLISHER_TASK is not None:
            try:
                await asyncio.wait_for(_PUBLISHER_TASK, timeout=2.0)
            except Exception:
                _PUBLISHER_TASK.cancel()
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

def _parse_form_json_fields(keywords: str, dependencies: str, platforms: str) -> tuple[list, dict, list]:
    """Parse JSON-encoded form fields or raise 400."""
    try:
        return json.loads(keywords), json.loads(dependencies), json.loads(platforms)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON in keywords/dependencies/platforms")

async def _ensure_package_absent(database: DatabaseInterface, name: str, version: str) -> None:
    """Raise 409 if package@version already exists."""
    if await database.get_package(name, version):
        raise HTTPException(409, f"Package {name} version {version} already exists")

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
    # Re-fetch latest to obtain the inserted row (or return from create if you adapt it)
    created = await database.get_package(file.filename, "0.1.0")
    if created and created.id is not None:
        await _enqueue_publish_job(database, created.id, created.name, created.version)
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

    kw_list, dep_map, plat_list = _parse_form_json_fields(keywords, dependencies, platforms)
    await _ensure_package_absent(database, name, version)

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
    # Enqueue for auto-publish (best-effort) — processed only if BASHMAN_AUTO_PUBLISH=1
    try:
        await _enqueue_publish_job(database, int(pkg_id), name, version)
    except Exception:
        pass

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
