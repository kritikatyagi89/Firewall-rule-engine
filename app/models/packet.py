from __future__ import annotations

import datetime
from typing import Any, Dict, Optional


class Packet:
    """Represents a network packet used for firewall matching."""

    allowed_protocols = {"TCP", "UDP", "ICMP"}

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload: Optional[str] = None,
        timestamp: Optional[datetime.datetime] = None,
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload = payload
        self.timestamp = timestamp or datetime.datetime.utcnow()
        self.validate()

    def to_dict(self) -> Dict[str, Any]:
        """Return the packet as a serializable dictionary."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Packet":
        """Create a Packet instance from a dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.datetime.fromisoformat(timestamp)

        return cls(
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=int(data["src_port"]),
            dst_port=int(data["dst_port"]),
            protocol=data["protocol"],
            payload=data.get("payload"),
            timestamp=timestamp,
        )

    def validate(self) -> None:
        """Validate packet fields and raise ValueError for invalid values."""
        if self.protocol not in self.allowed_protocols:
            raise ValueError(f"Invalid protocol: {self.protocol}")

        for name, port in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise ValueError(f"{name} must be an integer between 1 and 65535, got {port}")

    def __repr__(self) -> str:
        """Return a concise string representation for debugging."""
        return (
            f"<Packet protocol={self.protocol} src={self.src_ip}:{self.src_port} "
            f"dst={self.dst_ip}:{self.dst_port}>"
        )
