"""
Abstract Signing Engine Interface and Shared Result Contracts.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class SigningResult:
    """Standardized result returned by any SigningEngine implementation."""
    success: bool
    output_path: Optional[Path] = None
    bundle_id: Optional[str] = None
    bundle_name: Optional[str] = None
    bundle_version: Optional[str] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    execution_time_seconds: float = 0.0
    engine_used: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class SigningEngine(ABC):
    """Abstract interface defining required methods for all signing engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return engine identifier, e.g. 'zsign' or 'fallback'."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if engine prerequisites (binaries, libraries) are present."""
        pass

    @abstractmethod
    async def sign(
        self,
        ipa_path: Path,
        p12_path: Path,
        p12_password: str,
        provisioning_path: Path,
        output_path: Path,
        bundle_id: Optional[str] = None,
        bundle_name: Optional[str] = None,
        bundle_version: Optional[str] = None,
        entitlements_path: Optional[Path] = None,
        compression_level: int = 1,
        temp_dir: Optional[Path] = None,
        timeout_seconds: float = 300.0,
    ) -> SigningResult:
        """
        Execute iOS IPA package re-signing.
        """
        pass
