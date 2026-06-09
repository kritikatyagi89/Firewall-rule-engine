import datetime
import pytest

from app.database.db import Database
from app.models.rule import Rule


def make_rule(**kwargs):
    data = {
        "name": kwargs.get("name", "Test Rule"),
        "action": kwargs.get("action", "deny"),
        "protocol": kwargs.get("protocol", "TCP"),
        "src_ip": kwargs.get("src_ip", "*"),
        "dst_ip": kwargs.get("dst_ip", "*"),
        "src_port": kwargs.get("src_port", None),
        "dst_port": kwargs.get("dst_port", None),
        "priority": kwargs.get("priority", 100),
    }
    return Rule(**data)


def test_save_get_and_delete_rule():
    db = Database(db_path=":memory:")
    rule = make_rule(name="Database Rule", action="allow", priority=2)
    db.save_rule(rule)

    loaded = db.get_rule_by_id(rule.id)
    assert loaded is not None
    assert loaded["id"] == rule.id
    assert loaded["name"] == "Database Rule"
    assert loaded["priority"] == 2

    all_rules = db.get_all_rules()
    assert len(all_rules) == 1
    assert all_rules[0]["id"] == rule.id

    db.delete_rule(rule.id)
    assert db.get_rule_by_id(rule.id) is None
    assert db.get_all_rules() == []
    db.connection.close()


def test_log_packet_and_get_audit_log():
    db = Database(db_path=":memory:")
    result = {
        "action": "allow",
        "matched_rule": "123",
        "packet": {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 5000,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "test",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        },
        "eval_time_ms": 1.23,
    }
    db.log_packet(result)

    entries = db.get_audit_log(limit=10)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action"] == "allow"
    assert entry["matched_rule_id"] == "123"
    assert entry["protocol"] == "TCP"

    db.clear_audit_log()
    assert db.get_audit_log(limit=10) == []
    db.connection.close()


def test_database_error_handling_when_connection_closed():
    db = Database(db_path=":memory:")
    rule = make_rule(name="Error Rule", action="allow")
    result = {
        "action": "deny",
        "matched_rule": None,
        "packet": {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1,
            "dst_port": 2,
            "protocol": "TCP",
            "payload": None,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        },
        "eval_time_ms": 0.0,
    }

    db.connection.close()

    with pytest.raises(RuntimeError):
        db.save_rule(rule)
    with pytest.raises(RuntimeError):
        db.delete_rule(rule.id)
    with pytest.raises(RuntimeError):
        db.get_all_rules()
    with pytest.raises(RuntimeError):
        db.get_rule_by_id(rule.id)
    with pytest.raises(RuntimeError):
        db.log_packet(result)
    with pytest.raises(RuntimeError):
        db.get_audit_log()
    with pytest.raises(RuntimeError):
        db.clear_audit_log()
