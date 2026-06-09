import datetime

import pytest

from app.models.packet import Packet
from app.models.rule import Rule


def test_rule_creation_valid():
    rule = Rule(
        name="Block SSH",
        action="deny",
        protocol="TCP",
        src_ip="192.168.1.0",
        dst_ip="10.0.0.1",
        src_port=22,
        dst_port=22,
        priority=5,
    )

    assert rule.id is not None
    assert rule.name == "Block SSH"
    assert rule.action == "deny"
    assert rule.protocol == "TCP"
    assert rule.src_ip == "192.168.1.0"
    assert rule.dst_ip == "10.0.0.1"
    assert rule.src_port == 22
    assert rule.dst_port == 22
    assert rule.priority == 5
    assert isinstance(rule.created_at, datetime.datetime)


def test_rule_invalid_action():
    with pytest.raises(ValueError, match="Invalid action"):
        Rule(name="Block", action="block", protocol="TCP")


def test_rule_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid protocol"):
        Rule(name="Bad Proto", action="deny", protocol="FTP")


def test_rule_to_dict():
    rule = Rule(name="Log ICMP", action="log", protocol="ICMP")
    result = rule.to_dict()

    assert set(result.keys()) == {
        "id",
        "name",
        "action",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "priority",
        "created_at",
    }
    assert result["name"] == "Log ICMP"
    assert result["action"] == "log"
    assert result["protocol"] == "ICMP"


def test_rule_from_dict():
    original = Rule(
        name="Allow Any",
        action="allow",
        protocol="ANY",
        src_ip="*",
        dst_ip="*",
        src_port=None,
        dst_port=None,
        priority=10,
    )
    data = original.to_dict()
    recreated = Rule.from_dict(data)

    assert recreated.id == original.id
    assert recreated.name == original.name
    assert recreated.action == original.action
    assert recreated.protocol == original.protocol
    assert recreated.src_ip == original.src_ip
    assert recreated.dst_ip == original.dst_ip
    assert recreated.src_port is original.src_port
    assert recreated.dst_port is original.dst_port
    assert recreated.priority == original.priority
    assert recreated.created_at == original.created_at


def test_packet_creation_valid():
    packet = Packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        payload="hello",
    )

    assert packet.src_ip == "192.168.1.10"
    assert packet.dst_ip == "10.0.0.5"
    assert packet.src_port == 50000
    assert packet.dst_port == 80
    assert packet.protocol == "TCP"
    assert packet.payload == "hello"
    assert isinstance(packet.timestamp, datetime.datetime)


def test_packet_invalid_port():
    with pytest.raises(ValueError, match="src_port must be an integer"):
        Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=99999, dst_port=80, protocol="TCP")


def test_packet_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid protocol"):
        Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol="HTTP")
