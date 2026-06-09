from __future__ import annotations

import datetime
import sqlite3
from typing import Any, Dict, List, Optional

from app.models.rule import Rule


class Database:
    """SQLite-backed persistence layer for firewall rules and audit logs."""

    def __init__(self, db_path: str = "firewall.db") -> None:
        self.db_path = db_path
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self._create_tables()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to connect to database {self.db_path}: {exc}") from exc

    def _create_tables(self) -> None:
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    priority INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    action TEXT NOT NULL,
                    matched_rule_id TEXT,
                    eval_time_ms REAL
                )
                """
            )
            self.connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to create database tables: {exc}") from exc

    def save_rule(self, rule: Rule) -> None:
        """Insert a rule into the rules table."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT INTO rules (
                    id, name, action, protocol, src_ip, dst_ip, src_port, dst_port, priority, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.id,
                    rule.name,
                    rule.action,
                    rule.protocol,
                    rule.src_ip,
                    rule.dst_ip,
                    rule.src_port,
                    rule.dst_port,
                    rule.priority,
                    rule.created_at.isoformat(),
                ),
            )
            self.connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to save rule {rule.id}: {exc}") from exc

    def delete_rule(self, rule_id: str) -> None:
        """Delete a rule by its ID."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            self.connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to delete rule {rule_id}: {exc}") from exc

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Return all saved rules as a list of dictionaries."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM rules ORDER BY priority ASC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to load rules: {exc}") from exc

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Return a rule dictionary by ID or None if it does not exist."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM rules WHERE id = ?", (rule_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to retrieve rule {rule_id}: {exc}") from exc

    def log_packet(self, result: Dict[str, Any]) -> None:
        """Insert a packet evaluation result into the audit log."""
        try:
            packet = result.get("packet", {})
            timestamp = packet.get("timestamp") or datetime.datetime.utcnow().isoformat()
            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, matched_rule_id, eval_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    packet.get("src_ip"),
                    packet.get("dst_ip"),
                    packet.get("src_port"),
                    packet.get("dst_port"),
                    packet.get("protocol"),
                    result.get("action"),
                    result.get("matched_rule"),
                    result.get("eval_time_ms"),
                ),
            )
            self.connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to log packet result: {exc}") from exc

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return the last N audit log entries."""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to load audit log: {exc}") from exc

    def clear_audit_log(self) -> None:
        """Delete all entries from the audit log."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM audit_log")
            self.connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to clear audit log: {exc}") from exc
