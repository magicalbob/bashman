from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from ..models import PackageMetadata

class DatabaseInterface(ABC):
    """Abstract base class for database implementations"""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the database (create tables, etc.)"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close database connections"""
        pass

    # Package CRUD operations
    @abstractmethod
    async def create_package(self, package: PackageMetadata, content: bytes) -> str:
        """Create a new package with script content, return package ID"""
        pass

    @abstractmethod
    async def get_package(self,
                          name: str,
                          version: Optional[str] = None) -> Optional[PackageMetadata]:
        """Get a package by name and optionally version"""
        pass

    @abstractmethod
    async def get_package_content(self,
                                  name: str,
                                  version: Optional[str] = None) -> Optional[bytes]:
        """Get the script content for a package"""
        pass

    @abstractmethod
    async def get_package_with_content(self,
                                       name: str,
                  version: Optional[str] = None) -> Optional[Tuple[PackageMetadata, bytes]]:
        """Get both package metadata and content"""
        pass

    @abstractmethod
    async def list_packages(self,
                            limit: int = 100,
                            offset: int = 0,
                            status: Optional[str] = None) -> List[PackageMetadata]:
        """List packages with pagination and optional status filtering"""
        pass

    @abstractmethod
    async def update_package(self, name: str, version: str, updates: Dict[str, Any]) -> bool:
        """Update package metadata"""
        pass

    @abstractmethod
    async def delete_package(self, name: str, version: str) -> bool:
        """Delete a specific package version"""
        pass

    # Search and discovery
    @abstractmethod
    async def search_packages(self, query: str, limit: int = 50) -> List[PackageMetadata]:
        """Search packages by name, description, or keywords"""
        pass

    @abstractmethod
    async def get_package_versions(self, name: str) -> List[str]:
        """Get all versions of a package"""
        pass

    # Statistics and analytics
    @abstractmethod
    async def get_package_count(self) -> int:
        """Get total number of packages"""
        pass

    @abstractmethod
    async def get_trending_packages(self, days: int = 7, limit: int = 10) -> List[PackageMetadata]:
        """Get trending packages based on recent activity"""
        pass

    @abstractmethod
    async def record_download(
        self,
        package_id: int,
        user_agent: str = None,
        ip_address: str = None,
    ) -> None:
        pass
