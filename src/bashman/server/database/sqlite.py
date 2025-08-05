import sqlite3
import aiosqlite
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import os

from .base import DatabaseInterface
from ..models import PackageMetadata

class SQLiteDatabase(DatabaseInterface):
    """SQLite implementation of the database interface"""
    
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
    
    async def _create_schema(self) -> None:
        """Create database tables"""
        schema = """
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
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT,
            status TEXT DEFAULT 'quarantined', -- quarantined, published, deprecated
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            UNIQUE(name, version)
        );
        
        CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
        CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(status);
        CREATE INDEX IF NOT EXISTS idx_packages_created_at ON packages(created_at);
        CREATE INDEX IF NOT EXISTS idx_packages_download_count ON packages(download_count);
        
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
        """
        
        await self._db.executescript(schema)
        await self._db.commit()
    
    async def create_package(self, package: PackageMetadata) -> str:
        """Create a new package"""
        query = """
        INSERT INTO packages (
            name, version, description, author, homepage, repository, 
            license, keywords, dependencies, platforms, shell_version,
            file_path, file_size, file_hash, status
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
            package.file_path,
            package.file_size,
            package.file_hash,
            package.status
        )
        
        cursor = await self._db.execute(query, values)
        await self._db.commit()
        return str(cursor.lastrowid)
    
    async def get_package(self, name: str, version: Optional[str] = None) -> Optional[PackageMetadata]:
        """Get a package by name and optionally version"""
        if version:
            query = "SELECT * FROM packages WHERE name = ? AND version = ? AND status != 'deleted'"
            params = (name, version)
        else:
            # Get latest version
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
            return self._row_to_package_metadata(row)
        return None
    
    async def list_packages(self, limit: int = 100, offset: int = 0) -> List[PackageMetadata]:
        """List all packages with pagination"""
        query = """
        SELECT * FROM packages 
        WHERE status = 'published'
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
        """
        
        cursor = await self._db.execute(query, (limit, offset))
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
        """Search packages by name, description, or keywords"""
        search_query = """
        SELECT * FROM packages 
        WHERE status = 'published' AND (
            name LIKE ? OR 
            description LIKE ? OR 
            keywords LIKE ?
        )
        ORDER BY 
            CASE WHEN name LIKE ? THEN 1 ELSE 2 END,
            download_count DESC,
            created_at DESC
        LIMIT ?
        """
        
        search_term = f"%{query}%"
        name_priority = f"{query}%"  # Exact name matches get priority
        
        cursor = await self._db.execute(
            search_query, 
            (search_term, search_term, search_term, name_priority, limit)
        )
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
        SELECT p.*, COUNT(pd.id) as recent_downloads
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
        
        return [self._row_to_package_metadata(row[:-1]) for row in rows]  # Exclude recent_downloads column
    
    async def record_download(self, package_id: int, user_agent: str = None, ip_address: str = None) -> None:
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
        """Convert database row to PackageMetadata object"""
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
            file_path=row[12],
            file_size=row[13],
            file_hash=row[14],
            status=row[15],
            created_at=datetime.fromisoformat(row[16]) if row[16] else None,
            updated_at=datetime.fromisoformat(row[17]) if row[17] else None,
            download_count=row[18] or 0
        )
