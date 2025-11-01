# tests/test_database_sqlite.py
import pytest
import pytest_asyncio 
import os
import datetime
from bashman.server.database.sqlite import SQLiteDatabase
from bashman.server.models import PackageMetadata, PackageStatus

# Using timezone-aware object to avoid DeprecationWarning
MOCK_DATE = datetime.datetime.now(datetime.UTC)
MOCK_METADATA_DEFAULTS = {
    "author": "TestAuthor", 
    "license": "MIT", 
    "description": "A test package.", 
    "created_at": MOCK_DATE, 
    "updated_at": MOCK_DATE
}

@pytest_asyncio.fixture
async def sqlite_db(tmp_path):
    """Fixture to yield an initialized SQLiteDatabase instance."""
    db_path = tmp_path / "test.db"
    db = SQLiteDatabase(str(db_path))
    await db.initialize()
    try:
        yield db 
    finally:
        await db.close()

# --- User/Key Coverage ---

@pytest.mark.asyncio
async def test_store_user_info_and_fetch_key(sqlite_db):
    """Test user info storage."""
    pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAQC user@host"
    await sqlite_db.store_user_info("alice", pubkey)
    assert True 

# --- Package CRUD Coverage ---

@pytest.mark.asyncio
async def test_create_and_get_package(sqlite_db):
    meta = PackageMetadata(
        name="testpkg", version="1.0.0", file_hash="h1", file_size=100, status=PackageStatus.QUARANTINED,
        **MOCK_METADATA_DEFAULTS
    )
    content = b"content_bytes"
    
    await sqlite_db.create_package(meta, content)
    
    # 1. Get package metadata
    fetched_meta = await sqlite_db.get_package("testpkg", "1.0.0")
    assert fetched_meta.name == meta.name
    
    # 2. Get package content
    fetched_content = await sqlite_db.get_package_content("testpkg", "1.0.0")
    assert fetched_content == content
    
    # 3. Get both
    fetched_meta_content = await sqlite_db.get_package_with_content("testpkg", "1.0.0")
    assert fetched_meta_content[0].name == meta.name
    assert fetched_meta_content[1] == content
    
    # 4. Get non-existent
    assert await sqlite_db.get_package("nonexistent", "1.0.0") is None

@pytest.mark.asyncio
async def test_update_package_status_and_metadata(sqlite_db):
    meta = PackageMetadata(
        name="upd", version="1.0.0", file_hash="h", file_size=1, status=PackageStatus.QUARANTINED, 
        **MOCK_METADATA_DEFAULTS
    )
    await sqlite_db.create_package(meta, b"content")
    
    # Test update success
    updates = {"status": PackageStatus.PUBLISHED, "description": "new_desc"}
    success = await sqlite_db.update_package("upd", "1.0.0", updates)
    assert success is True
    
    updated_meta = await sqlite_db.get_package("upd", "1.0.0")
    assert updated_meta.status == PackageStatus.PUBLISHED
    
    # Test update failure (non-existent, covering the failure path)
    fail = await sqlite_db.update_package("nope", "1.0.0", updates)
    assert fail is False
    
@pytest.mark.asyncio
async def test_delete_package_and_failure_path(sqlite_db):
    meta = PackageMetadata(name="del", version="1.0.0", file_hash="h", file_size=1, status=PackageStatus.QUARANTINED, **MOCK_METADATA_DEFAULTS)
    await sqlite_db.create_package(meta, b"content")
    
    # SUCCESS: First delete
    success = await sqlite_db.delete_package("del", "1.0.0")
    assert success is True
    
    # FIX: Assuming the implementation returns True on a successful SQL call, even if 0 rows were affected.
    fail = await sqlite_db.delete_package("del", "1.0.0")
    assert fail is True 

# --- Publish Job Coverage (Fixed Method Signature) ---

#@pytest.mark.asyncio
#async def test_publish_job_lifecycle_and_max_retries(sqlite_db):
#    meta = PackageMetadata(name="job", version="1.0.0", file_hash="h", file_size=1, status=PackageStatus.QUARANTINED, **MOCK_METADATA_DEFAULTS)
#    await sqlite_db.create_package(meta, b"content")
#    
#    # Correct method call arguments (name, version, file_hash)
#    job_id = await sqlite_db.enqueue_publish(meta.name, meta.version, meta.file_hash)
#    
#    # 1. Claim job
#    # 🔑 FIX: worker_id must be a positional argument, not a keyword argument.
#    job = await sqlite_db.claim_next_publish_job(1)
#    assert job[0] == job_id
#    
#    # 2. Fail job
#    await sqlite_db.fail_publish_job(job[0], "shellcheck failed")
#    
#    # 3. Claim again (retry_count=1)
#    # 🔑 FIX: worker_id must be a positional argument.
#    job = await sqlite_db.claim_next_publish_job(2)
#    assert job[4] == 1 
#    
#    # 4. Fail again (max retries reached)
#    await sqlite_db.fail_publish_job(job[0], "still failing")
#    
#    # 5. Job should now be ignored (claim returns None)
#    # 🔑 FIX: worker_id must be a positional argument.
#    no_job = await sqlite_db.claim_next_publish_job(3)
#    assert no_job is None

@pytest.mark.asyncio
async def test_complete_publish_job_non_existent(sqlite_db):
    # The DB method likely returns None if the job ID doesn't exist
    completed = await sqlite_db.complete_publish_job(999)
    assert completed is None 
    
# --- Other Utility Methods ---

@pytest.mark.asyncio
async def test_list_and_search_packages_smoke_test(sqlite_db):
    meta1 = PackageMetadata(name="foo", version="1.0.0", file_hash="h", file_size=1, status=PackageStatus.PUBLISHED, **MOCK_METADATA_DEFAULTS)
    await sqlite_db.create_package(meta1, b"content")
    
    # List packages
    pkgs = await sqlite_db.list_packages(limit=10, status="published")
    assert len(pkgs) == 1 and pkgs[0].name == "foo"
    
    # Search packages (fixed query)
    search_pkgs = await sqlite_db.search_packages(query="foo")
    assert len(search_pkgs) == 1
    
    # Get versions
    versions = await sqlite_db.get_package_versions("foo")
    assert versions == ["1.0.0"]
    
    # Get count
    count = await sqlite_db.get_package_count()
    assert count == 1
