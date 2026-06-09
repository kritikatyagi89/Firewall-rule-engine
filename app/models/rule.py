from __future__ import annotations

import datetime
import uuid
from enum import Enum
from typing import Any, Dict, Optional


class RuleAction(str, Enum):
    """Allowed actions for a firewall rule."""

    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"


class RuleProtocol(str, Enum):
    """Allowed protocols for a firewall rule."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"


class Rule:
    """Represents a firewall rule with matching criteria and an action."""

    allowed_actions = {action.value for action in RuleAction}
    allowed_protocols = {protocol.value for protocol in RuleProtocol}

    def __init__(
        self,
        name: str,
        action: str,
        protocol: str = RuleProtocol.ANY.value,
        src_ip: str = "*",
        dst_ip: str = "*",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        priority: int = 100,
        created_at: Optional[datetime.datetime] = None,
        id: Optional[str] = None,
    ) -> None:
        self.id = id or str(uuid.uuid4())
        self.name = name
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.priority = priority
        self.created_at = created_at or datetime.datetime.utcnow()
        self.validate()

    def to_dict(self) -> Dict[str, Any]:
        """Return the rule as a serializable dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "action": self.action,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """Create a Rule instance from a dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.datetime.fromisoformat(created_at)

        return cls(
            id=data.get("id"),
            name=data["name"],
            action=data["action"],
            protocol=data.get("protocol", RuleProtocol.ANY.value),
            src_ip=data.get("src_ip", "*"),
            dst_ip=data.get("dst_ip", "*"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            priority=data.get("priority", 100),
            created_at=created_at,
        )

    def validate(self) -> None:
        """Validate the rule fields and raise ValueError for invalid values."""
        if self.action not in self.allowed_actions:
            raise ValueError(f"Invalid action: {self.action}")

        if self.protocol not in self.allowed_protocols:
            raise ValueError(f"Invalid protocol: {self.protocol}")

        if self.src_port is not None and not (1 <= self.src_port <= 65535):
            raise ValueError(f"src_port must be between 1 and 65535 or None, got {self.src_port}")

        if self.dst_port is not None and not (1 <= self.dst_port <= 65535):
            raise ValueError(f"dst_port must be between 1 and 65535 or None, got {self.dst_port}")

    def __repr__(self) -> str:
        """Return a concise string representation for debugging."""
        return (
            f"<Rule id={self.id} name={self.name!r} action={self.action} "
            f"protocol={self.protocol} priority={self.priority}>"
        )
