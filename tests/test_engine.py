import pytest

from app.engine.firewall import FirewallEngine
from app.models.packet import Packet
from app.models.rule import Rule


def make_rule(**kwargs):
    data = {
        "name": kwargs.get("name", "Rule"),
        "action": kwargs.get("action", "deny"),
        "protocol": kwargs.get("protocol", "TCP"),
        "src_ip": kwargs.get("src_ip", "*"),
        "dst_ip": kwargs.get("dst_ip", "*"),
        "src_port": kwargs.get("src_port", None),
        "dst_port": kwargs.get("dst_port", None),
        "priority": kwargs.get("priority", 100),
    }
    return Rule(**data)


def make_packet(**kwargs):
    return Packet(
        src_ip=kwargs.get("src_ip", "192.168.1.1"),
        dst_ip=kwargs.get("dst_ip", "10.0.0.1"),
        src_port=kwargs.get("src_port", 5000),
        dst_port=kwargs.get("dst_port", 80),
        protocol=kwargs.get("protocol", "TCP"),
        payload=kwargs.get("payload", "payload"),
    )


def test_add_rule():
    engine = FirewallEngine()
    rule = make_rule(name="Test", action="allow", protocol="TCP")
    engine.add_rule(rule)

    assert engine.get_all_rules() == [rule]


def test_remove_rule():
    engine = FirewallEngine()
    rule = make_rule(name="Delete", action="deny", protocol="TCP")
    engine.add_rule(rule)
    engine.remove_rule(rule.id)

    assert engine.get_all_rules() == []
    assert engine.get_rule_by_id(rule.id) is None


def test_remove_nonexistent_rule():
    engine = FirewallEngine()
    with pytest.raises(KeyError):
        engine.remove_rule("missing-id")


def test_priority_ordering():
    engine = FirewallEngine()
    rule_low = make_rule(name="Low", priority=10)
    rule_high = make_rule(name="High", priority=1)
    rule_mid = make_rule(name="Mid", priority=5)

    engine.add_rule(rule_low)
    engine.add_rule(rule_high)
    engine.add_rule(rule_mid)

    all_rules = engine.get_all_rules()
    assert all_rules == [rule_high, rule_mid, rule_low]


def test_evaluate_allow():
    engine = FirewallEngine()
    rule = make_rule(name="Allow HTTP", action="allow", protocol="TCP", dst_port=80)
    engine.add_rule(rule)
    packet = make_packet(dst_port=80)

    result = engine.evaluate_packet(packet)
    assert result["action"] == "allow"
    assert result["matched_rule"] == rule.id


def test_evaluate_deny():
    engine = FirewallEngine()
    rule = make_rule(name="Block SMTP", action="deny", protocol="TCP", dst_port=25)
    engine.add_rule(rule)
    packet = make_packet(dst_port=25)

    result = engine.evaluate_packet(packet)
    assert result["action"] == "deny"
    assert result["matched_rule"] == rule.id


def test_evaluate_no_match_default_deny():
    engine = FirewallEngine()
    packet = make_packet(dst_port=8080)

    result = engine.evaluate_packet(packet)
    assert result["action"] == "deny"
    assert result["matched_rule"] is None


def test_evaluate_wildcard_ip():
    engine = FirewallEngine()
    rule = make_rule(name="Wildcard", action="allow", protocol="TCP", src_ip="*", dst_ip="10.0.0.1")
    engine.add_rule(rule)
    packet = make_packet(src_ip="1.2.3.4", dst_ip="10.0.0.1")

    result = engine.evaluate_packet(packet)
    assert result["action"] == "allow"
    assert result["matched_rule"] == rule.id


def test_evaluate_any_protocol():
    engine = FirewallEngine()
    rule = make_rule(name="Any Proto", action="allow", protocol="ANY", dst_port=53)
    engine.add_rule(rule)
    packet = make_packet(protocol="UDP", dst_port=53)

    result = engine.evaluate_packet(packet)
    assert result["action"] == "allow"
    assert result["matched_rule"] == rule.id


def test_process_batch():
    engine = FirewallEngine()
    rule = make_rule(name="Allow All", action="allow", protocol="ANY")
    engine.add_rule(rule)
    packets = [make_packet() for _ in range(5)]

    batch_result = engine.process_batch(packets)
    assert len(batch_result["results"]) == 5
    assert batch_result["summary"]["allow"] == 5
    assert batch_result["summary"]["deny"] == 0
    assert batch_result["summary"]["log"] == 0


def test_eval_time_recorded():
    engine = FirewallEngine()
    rule = make_rule(name="Allow Time", action="allow", protocol="ANY")
    engine.add_rule(rule)
    packet = make_packet()

    result = engine.evaluate_packet(packet)
    assert isinstance(result["eval_time_ms"], float)
    assert result["eval_time_ms"] >= 0.0


def test_ips_ids_alert_trigger():
    engine = FirewallEngine()
    rule = make_rule(name="Block SSH", action="deny", protocol="TCP", dst_port=22)
    engine.add_rule(rule)
    packet = make_packet(dst_port=22)

    result = engine.evaluate_packet(packet)
    assert result["action"] == "deny"
    assert result["matched_rule"] == rule.id
