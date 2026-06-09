from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from app.models.packet import Packet
from app.models.rule import Rule


class FirewallEngine:
    """Core firewall engine for rule storage and packet evaluation."""

    def __init__(self) -> None:
        self._rules: List[Rule] = []

    def add_rule(self, rule: Rule) -> None:
        """Add a rule and keep rules sorted by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda item: item.priority)

    def remove_rule(self, rule_id: str) -> None:
        """Remove a rule by its ID or raise KeyError if not found."""
        for index, rule in enumerate(self._rules):
            if rule.id == rule_id:
                del self._rules[index]
                return
        raise KeyError(f"Rule not found: {rule_id}")

    def get_all_rules(self) -> List[Rule]:
        """Return all rules sorted by priority."""
        return list(self._rules)

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Return a rule by ID or None if not found."""
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def evaluate_packet(self, packet: Packet) -> Dict[str, Any]:
        """Evaluate a packet against stored rules and return the decision."""
        start = time.perf_counter()
        for rule in self._rules:
            if self._match_rule(rule, packet):
                elapsed_ms = (time.perf_counter() - start) * 1000
                return {
                    "action": rule.action,
                    "matched_rule": rule.id,
                    "packet": packet.to_dict(),
                    "eval_time_ms": round(elapsed_ms, 3),
                }

        elapsed_ms = (time.perf_counter() - start) * 1000
        return {
            "action": "deny",
            "matched_rule": None,
            "packet": packet.to_dict(),
            "eval_time_ms": round(elapsed_ms, 3),
        }

    def process_batch(self, packets: List[Packet]) -> Dict[str, Any]:
        """Process a batch of packets and return results and summary counts."""
        results: List[Dict[str, Any]] = []
        summary = {"allow": 0, "deny": 0, "log": 0}

        for packet in packets:
            result = self.evaluate_packet(packet)
            results.append(result)
            action = result.get("action")
            if action in summary:
                summary[action] += 1

        return {
            "results": results,
            "summary": summary,
        }

    def _match_rule(self, rule: Rule, packet: Packet) -> bool:
        """Return True if the packet matches the rule criteria."""
        if rule.protocol != "ANY" and rule.protocol != packet.protocol:
            return False

        if rule.src_ip != "*" and rule.src_ip != packet.src_ip:
            return False

        if rule.dst_ip != "*" and rule.dst_ip != packet.dst_ip:
            return False

        if rule.src_port is not None and rule.src_port != packet.src_port:
            return False

        if rule.dst_port is not None and rule.dst_port != packet.dst_port:
            return False

        return True
