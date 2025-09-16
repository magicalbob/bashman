from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

class PackageStatus(str, Enum):
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    DELETED = "deleted"

class Package(BaseModel):
    """Basic package model for API responses"""
    name: str
    version: str
    description: str

class PackageMetadata(BaseModel):
    """Complete package metadata model - no file_path since content is in database"""
    id: Optional[int] = None
    name: str
    version: str
    description: str
    author: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    keywords: List[str] = []
    dependencies: Dict[str, str] = {}
    platforms: List[str] = []
    shell_version: Optional[str] = None
    file_path: Optional[str] = None  # Deprecated, always None now
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    status: PackageStatus = PackageStatus.QUARANTINED
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    download_count: int = 0

class CreatePackageRequest(BaseModel):
    """Request model for creating packages"""
    name: str
    version: str
    description: str
    author: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    keywords: List[str] = []
    dependencies: Dict[str, str] = {}
    platforms: List[str] = []
    shell_version: Optional[str] = None

class PackageSearchResult(BaseModel):
    """Search result with relevance scoring"""
    package: PackageMetadata
    relevance_score: Optional[float] = None

class RegistryStats(BaseModel):
    """Registry statistics model"""
    total_packages: int
    published_packages: int
    quarantined_packages: int
    total_downloads: int
    storage_type: str = "database"
