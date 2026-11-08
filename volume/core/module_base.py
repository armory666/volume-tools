from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple

from volume.core import config


class BaseModule(ABC):
    """Base class for every VOLUME tool.

    A module returns a dict shaped like:
        {"module", "title", "source", "confidence", "status", "rows": [(key, value)]}
    """

    # ---- identity ---------------------------------------------------------
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique ID (e.g., 'ip_lookup')."""

    @property
    @abstractmethod
    def label(self) -> str:
        """Display name (e.g., 'IP Intel')."""

    @property
    @abstractmethod
    def category(self) -> str:
        """Tab it belongs to (OSINT, BREACH, MALICIOUS, CSINT, ...)."""

    # ---- metadata ---------------------------------------------------------
    @property
    def description(self) -> str:
        return ""

    @property
    def min_tier(self) -> str:
        """Minimum tier required: FREE, PREMIUM, DETECTIVE, INDUSTRIAL, LIFETIME."""
        return "FREE"

    @property
    def credit_cost(self) -> int:
        return 1

    @property
    def order(self) -> int:
        return 100

    @property
    def tags(self) -> List[str]:
        return []

    @property
    def requires_key(self) -> Tuple[str, ...]:
        """Environment/keys.json names this module can use (empty = no key needed)."""
        return ()

    # ---- input contract ---------------------------------------------------
    @property
    def inputs(self) -> List[str]:
        return []

    @property
    def optional_inputs(self) -> Dict[str, str]:
        return {}

    @property
    def input_prompts(self) -> Dict[str, str]:
        return {}

    @property
    def secret_inputs(self) -> Tuple[str, ...]:
        """Fields that should be read without echoing (passwords/tokens)."""
        return ()

    @property
    def multiline_inputs(self) -> Tuple[str, ...]:
        """Fields that need a multi-line paste (read until a blank line)."""
        return ()

    @abstractmethod
    def run(self, case, **kwargs) -> Dict[str, Any]:
        """Execute the module."""

    def pivots(self, result: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Return linked entities for the case graph."""
        return []

    # ---- helpers ----------------------------------------------------------
    def api_key(self, *names) -> str:
        for name in names or self.requires_key:
            value = config.get_key(name)
            if value:
                return value
        return ""

    def key_required(self, names, help_url: str = "", title: str = None,
                     extra_rows=None) -> Dict[str, Any]:
        names = tuple(names or self.requires_key)
        rows = list(extra_rows or [])
        rows.append(("Result", f"Missing API key: {', '.join(names)}"))
        rows.append(("Setup", f"Set {names[0].upper()}_API_KEY in .env "
                               f"or add {{\"{names[0]}\": \"...\"}} to data/keys.json"))
        if help_url:
            rows.append(("Get a key", help_url))
        return {
            "module": self.id,
            "title": title or self.label,
            "source": "configuration",
            "confidence": "low",
            "status": "key_required",
            "rows": rows,
        }

    def result(self, title=None, rows=None, source="", confidence="medium",
               status="ok", **extra) -> Dict[str, Any]:
        data = {
            "module": self.id,
            "title": title or self.label,
            "source": source or "VOLUME",
            "confidence": confidence,
            "status": status,
            "rows": list(rows or []),
        }
        data.update(extra)
        return data
