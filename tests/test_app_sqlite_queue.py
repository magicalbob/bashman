import tempfile, os, pytest
from bashman.server.database.sqlite import SQLiteDatabase

@pytest.mark.asyncio
async def test_enqueue_publish_rollback_on_error(tmp_path, monkeypatch):
    dbf = tmp_path / "test.db"
    db = SQLiteDatabase(str(dbf))
    await db.initialize()
    # make execute raise inside enqueue_publish to trigger rollback path
    orig_execute = db._db.execute
    async def bad_execute(*a, **k):
        raise Exception("boom")
    monkeypatch.setattr(db._db, "execute", bad_execute)
    # Should not raise
    await db.enqueue_publish(1, "n", "v")
    # restore and clean up
    monkeypatch.setattr(db._db, "execute", orig_execute)
    await db.close()

@pytest.mark.asyncio
async def test_claim_next_publish_job_empty(tmp_path):
    db = SQLiteDatabase(str(tmp_path/"x.db"))
    await db.initialize()
    res = await db.claim_next_publish_job()
    assert res is None
    await db.close()
