import aiosqlite
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import json
import hashlib
from typing import Optional as _Opt

from .base import DatabaseInterface
from ..models import PackageMetadata

class SQLiteDatabase(DatabaseInterface):
    """SQLite implementation storing scripts as BLOBs"""

    def __init__(self, db_path: str = "bashman.db"):
        self.db_path = db_path
        self._db = None

    async def initialize(self) -> None:
        """Initialize SQLite database with schema"""
        self._db = await aiosqlite.connect(self.db_path)
        await self._create_schema()

    async def close(self) -> None:
        """Close database connection"""
        if self._db:
            await self._db.close()

    async def store_user_info(self, nickname: str, public_key: str) -> None:
        query = "INSERT INTO users (nickname, public_key, admin, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
        await self._db.execute(query, (nickname, public_key, 0))
        await self._db.commit()

    async def get_user(self, nickname: str) -> Optional[Dict[str, Any]]:
        """Return user record including admin flag or None."""
        cur = await self._db.execute(
            "SELECT id, nickname, public_key, admin, created_at FROM users WHERE nickname = ?",
            (nickname,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "nickname": row[1],
            "public_key": row[2],
            "admin": bool(row[3]),
            "created_at": row[4],
        }

    async def _create_schema(self) -> None:
        """Create database tables"""
        schema = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            nickname TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL UNIQUE,
            admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            author TEXT,
            homepage TEXT,
            repository TEXT,
            license TEXT,
            keywords TEXT, -- JSON array
            dependencies TEXT, -- JSON object
            platforms TEXT, -- JSON array
            shell_version TEXT,
            content BLOB NOT NULL, -- Script content stored as BLOB
            file_size INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            status TEXT DEFAULT 'quarantined', -- quarantined, published, deprecated, deleted
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            UNIQUE(name, version)
        );

        CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
        CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(status);
        CREATE INDEX IF NOT EXISTS idx_packages_created_at ON packages(created_at);
        CREATE INDEX IF NOT EXISTS idx_packages_download_count ON packages(download_count);
        CREATE INDEX IF NOT EXISTS idx_packages_hash ON packages(file_hash);

        -- Full-text search support
        CREATE VIRTUAL TABLE IF NOT EXISTS packages_fts USING fts5(
            name, description, keywords, content=packages, content_rowid=id
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS packages_fts_insert AFTER INSERT ON packages BEGIN
            INSERT INTO packages_fts(rowid, name, description, keywords)
            VALUES (new.id, new.name, new.description, new.keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS packages_fts_delete AFTER DELETE ON packages BEGIN
            INSERT INTO packages_fts(packages_fts, rowid, name, description, keywords)
            VALUES('delete', old.id, old.name, old.description, old.keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS packages_fts_update AFTER UPDATE ON packages BEGIN
            INSERT INTO packages_fts(packages_fts, rowid, name, description, keywords)
            VALUES('delete', old.id, old.name, old.description, old.keywords);
            INSERT INTO packages_fts(rowid, name, description, keywords)
            VALUES (new.id, new.name, new.description, new.keywords);
        END;

        CREATE TABLE IF NOT EXISTS package_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_id INTEGER NOT NULL,
            downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_agent TEXT,
            ip_address TEXT,
            FOREIGN KEY (package_id) REFERENCES packages (id)
        );

        CREATE INDEX IF NOT EXISTS idx_downloads_package_id ON package_downloads(package_id);
        CREATE INDEX IF NOT EXISTS idx_downloads_date ON package_downloads(downloaded_at);

        -- Simple publish queue
        CREATE TABLE IF NOT EXISTS publish_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',  -- pending | processing | done | failed
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            enqueued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (package_id) REFERENCES packages (id)
        );
        CREATE INDEX IF NOT EXISTS idx_pubq_status_enqueued ON publish_queue(status, enqueued_at);
        """

        await self._db.executescript(schema)
        await self._db.commit()

    def _calculate_hash(self, content: bytes) -> str:
        """Calculate SHA256 hash of content"""
        return hashlib.sha256(content).hexdigest()

    async def create_package(self, package: PackageMetadata, content: bytes) -> str:
        """Create a new package with script content"""
        file_hash = self._calculate_hash(content)
        file_size = len(content)

        query = """
        INSERT INTO packages (
            name, version, description, author, homepage, repository,
            license, keywords, dependencies, platforms, shell_version,
            content, file_size, file_hash, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        values = (
            package.name,
            package.version,
            package.description,
            package.author,
            package.homepage,
            package.repository,
            package.license,
            json.dumps(package.keywords) if package.keywords else None,
            json.dumps(package.dependencies) if package.dependencies else None,
            json.dumps(package.platforms) if package.platforms else None,
            package.shell_version,
            content,
            file_size,
            file_hash,
            package.status
        )

        cursor = await self._db.execute(query, values)
        await self._db.commit()
        return str(cursor.lastrowid)

    # -----------------------
    # Queue helpers (internal API; not on the abstract interface)
    # -----------------------
    async def enqueue_publish(self, package_id: int, name: str, version: str) -> None:
        """Enqueue a package for auto-publish (best-effort)."""
        try:
            await self._db.execute(
                "INSERT INTO publish_queue (package_id, name, version) VALUES (?, ?, ?)",
                (package_id, name, version),
            )
            await self._db.commit()
        except Exception:
            # Don't fail the main request path on queue errors
            await self._db.rollback()
            return

    async def claim_next_publish_job(self) -> _Opt[Tuple[int, int, str, str, int]]:
        """
        Claim the next pending job: returns (job_id, package_id, name, version, attempts)
        or None if nothing to do. (Best-effort; single-process races are negligible here.)
        """
        cur = await self._db.execute(
            "SELECT id, package_id, name, version, attempts "
            "FROM publish_queue WHERE status='pending' ORDER BY enqueued_at LIMIT 1"
        )
        row = await cur.fetchone()
        if not row:
            return None
        job_id = row[0]
        upd = await self._db.execute(
            "UPDATE publish_queue SET status='processing', attempts=attempts+1, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'",
            (job_id,),
        )
        await self._db.commit()
        if upd.rowcount == 0:
            return None
        return row  # (id, package_id, name, version, attempts)

    async def complete_publish_job(self, job_id: int) -> None:
        await self._db.execute(
            "UPDATE publish_queue SET status='done', updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (job_id,),
        )
        await self._db.commit()

    async def fail_publish_job(self, job_id: int, error: str) -> None:
        await self._db.execute(
            "UPDATE publish_queue SET status='failed', last_error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (error[:500], job_id),
        )
        await self._db.commit()

    async def get_package(self,
                          name: str,
                          version: Optional[str] = None) -> Optional[PackageMetadata]:
        """Get package metadata without content"""
        if version:
            query = """
            SELECT id, name, version, description, author, homepage, repository,
                   license, keywords, dependencies, platforms, shell_version,
                   file_size, file_hash, status, created_at, updated_at, download_count
            FROM packages
            WHERE name = ? AND version = ? AND status != 'deleted'
            """
            params = (name, version)
        else:
            query = """
            SELECT id, name, version, description, author, homepage, repository,
                   license, keywords, dependencies, platforms, shell_version,
                   file_size, file_hash, status, created_at, updated_at, download_count
            FROM packages
            WHERE name = ? AND status != 'deleted'
            ORDER BY created_at DESC
            LIMIT 1
            """
            params = (name,)

        cursor = await self._db.execute(query, params)
        row = await cursor.fetchone()

        if row:
            return self._row_to_package_metadata(row)
        return None

    async def get_package_content(self,
                                  name: str,
                                  version: Optional[str] = None) -> Optional[bytes]:
        """Get only the script content"""
        if version:
            query = (
                "SELECT content FROM packages "
                "WHERE name = ? AND version = ? AND status != 'deleted'"
            )
            params = (name, version)
        else:
            query = """
            SELECT content FROM packages
            WHERE name = ? AND status != 'deleted'
            ORDER BY created_at DESC
            LIMIT 1
            """
            params = (name,)

        cursor = await self._db.execute(query, params)
        row = await cursor.fetchone()

        return row[0] if row else None

    async def get_package_with_content(self,
                  name: str,
                  version: Optional[str] = None) -> Optional[Tuple[PackageMetadata, bytes]]:
        """Get both package metadata and content"""
        if version:
            query = "SELECT * FROM packages WHERE name = ? AND version = ? AND status != 'deleted'"
            params = (name, version)
        else:
            query = """
            SELECT * FROM packages
            WHERE name = ? AND status != 'deleted'
            ORDER BY created_at DESC
            LIMIT 1
            """
            params = (name,)

        cursor = await self._db.execute(query, params)
        row = await cursor.fetchone()

        if row:
            # Extract metadata (all columns except content which is at index 12)
            metadata_row = row[:12] + row[13:]  # Skip content column
            metadata = self._row_to_package_metadata(metadata_row)
            content = row[12]  # Content is at index 12
            return metadata, content
        return None

    async def list_packages(self,
                            limit: int = 100,
                            offset: int = 0,
                            status: Optional[str] = None) -> List[PackageMetadata]:
        """List packages with pagination and optional status filtering"""
        if status:
            query = """
            SELECT id, name, version, description, author, homepage, repository,
                   license, keywords, dependencies, platforms, shell_version,
                   file_size, file_hash, status, created_at, updated_at, download_count
            FROM packages
            WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """
            params = (status, limit, offset)
        else:
            query = """
            SELECT id, name, version, description, author, homepage, repository,
                   license, keywords, dependencies, platforms, shell_version,
                   file_size, file_hash, status, created_at, updated_at, download_count
            FROM packages
            WHERE status != 'deleted'
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """
            params = (limit, offset)

        cursor = await self._db.execute(query, params)
        rows = await cursor.fetchall()

        return [self._row_to_package_metadata(row) for row in rows]

    async def update_package(self, name: str, version: str, updates: Dict[str, Any]) -> bool:
        """Update package metadata"""
        if not updates:
            return False

        # Build dynamic update query
        set_clauses = []
        values = []

        for key, value in updates.items():
            if key in ['keywords', 'dependencies', 'platforms'] and value is not None:
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            values.append(value)

        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        values.extend([name, version])

        query = f"""
        UPDATE packages
        SET {', '.join(set_clauses)}
        WHERE name = ? AND version = ?
        """

        cursor = await self._db.execute(query, values)
        await self._db.commit()

        return cursor.rowcount > 0

    async def delete_package(self, name: str, version: str) -> bool:
        """Delete a specific package version (soft delete)"""
        query = """
        UPDATE packages
        SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
        WHERE name = ? AND version = ?
        """

        cursor = await self._db.execute(query, (name, version))
        await self._db.commit()

        return cursor.rowcount > 0

    async def search_packages(self, query: str, limit: int = 50) -> List[PackageMetadata]:
        """Search packages using FTS"""
        search_query = """
        SELECT p.id, p.name, p.version, p.description, p.author, p.homepage, p.repository,
               p.license, p.keywords, p.dependencies, p.platforms, p.shell_version,
               p.file_size, p.file_hash, p.status, p.created_at, p.updated_at, p.download_count
        FROM packages p
        JOIN packages_fts fts ON p.id = fts.rowid
        WHERE p.status = 'published' AND packages_fts MATCH ?
        ORDER BY rank, p.download_count DESC, p.created_at DESC
        LIMIT ?
        """

        cursor = await self._db.execute(search_query, (query, limit))
        rows = await cursor.fetchall()

        return [self._row_to_package_metadata(row) for row in rows]

    async def get_package_versions(self, name: str) -> List[str]:
        """Get all versions of a package"""
        query = """
        SELECT version FROM packages
        WHERE name = ? AND status != 'deleted'
        ORDER BY created_at DESC
        """

        cursor = await self._db.execute(query, (name,))
        rows = await cursor.fetchall()

        return [row[0] for row in rows]

    async def get_package_count(self) -> int:
        """Get total number of published packages"""
        query = "SELECT COUNT(DISTINCT name) FROM packages WHERE status = 'published'"
        cursor = await self._db.execute(query)
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def get_trending_packages(self, days: int = 7, limit: int = 10) -> List[PackageMetadata]:
        """Get trending packages based on recent downloads"""
        query = """
        SELECT p.id, p.name, p.version, p.description, p.author, p.homepage, p.repository,
               p.license, p.keywords, p.dependencies, p.platforms, p.shell_version,
               p.file_size, p.file_hash, p.status, p.created_at, p.updated_at, p.download_count,
               COUNT(pd.id) as recent_downloads
        FROM packages p
        LEFT JOIN package_downloads pd ON p.id = pd.package_id
            AND pd.downloaded_at > datetime('now', '-{} days')
        WHERE p.status = 'published'
        GROUP BY p.id
        ORDER BY recent_downloads DESC, p.download_count DESC
        LIMIT ?
        """.format(days)

        cursor = await self._db.execute(query, (limit,))
        rows = await cursor.fetchall()

        return [self._row_to_package_metadata(row[:-1]) for row in rows]

    async def record_download(self,
                              package_id: int,
                              user_agent: str = None,
                              ip_address: str = None) -> None:
        """Record a package download"""
        # Update download count
        await self._db.execute(
            "UPDATE packages SET download_count = download_count + 1 WHERE id = ?",
            (package_id,)
        )

        # Record download event
        await self._db.execute(
            "INSERT INTO package_downloads (package_id, user_agent, ip_address) VALUES (?, ?, ?)",
            (package_id, user_agent, ip_address)
        )

        await self._db.commit()

    def _row_to_package_metadata(self, row) -> PackageMetadata:
        """Convert database row to PackageMetadata object

        Expected row order:
        0: id, 1: name, 2: version, 3: description, 4: author, 5: homepage,
        6: repository, 7: license, 8: keywords, 9: dependencies, 10: platforms,
        11: shell_version, 12: file_size, 13: file_hash, 14: status,
        15: created_at, 16: updated_at, 17: download_count
        """
        return PackageMetadata(
            id=row[0],
            name=row[1],
            version=row[2],
            description=row[3],
            author=row[4],
            homepage=row[5],
            repository=row[6],
            license=row[7],
            keywords=json.loads(row[8]) if row[8] else [],
            dependencies=json.loads(row[9]) if row[9] else {},
            platforms=json.loads(row[10]) if row[10] else [],
            shell_version=row[11],
            file_path=None,  # No longer relevant
            file_size=row[12],
            file_hash=row[13],
            status=row[14],
            created_at=datetime.fromisoformat(row[15]) if row[15] else None,
            updated_at=datetime.fromisoformat(row[16]) if row[16] else None,
            download_count=row[17] or 0
        )
