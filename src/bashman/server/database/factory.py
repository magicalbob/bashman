from typing import Optional
from .base import DatabaseInterface
from .sqlite import SQLiteDatabase

class DatabaseFactory:
    """Factory for creating database instances"""

    @staticmethod
    def create_database(db_type: str = "sqlite", **kwargs) -> DatabaseInterface:
        """Create a database instance based on type"""
        if db_type.lower() == "sqlite":
            db_path = kwargs.get("db_path", "bashman.db")
            return SQLiteDatabase(db_path)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

    @staticmethod
    async def create_and_initialize(db_type: str = "sqlite", **kwargs) -> DatabaseInterface:
        """Create and initialize a database instance"""
        db = DatabaseFactory.create_database(db_type, **kwargs)
        await db.initialize()
        return db
