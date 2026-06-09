import pytest

from flask import current_app

from app import create_app
from app.api import routes
from app.api.routes import get_int, sanitize_string


@pytest.fixture
def app():
    app = create_app({"DATABASE_PATH": ":memory:"})
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_get_rules_empty(client):
    response = client.get("/api/rules")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert payload["data"] == []


def test_create_rule_valid(client):
    rule_data = {
        "name": "Block HTTP",
        "action": "deny",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 80,
        "priority": 1,
    }
    response = client.post("/api/rules", json=rule_data)
    payload = response.get_json()

    assert response.status_code == 201
    assert payload["status"] == "success"
    assert payload["data"]["name"] == "Block HTTP"
    assert payload["data"]["action"] == "deny"


def test_create_rule_missing_field(client):
    rule_data = {
        "name": "Missing Action",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "priority": 1,
    }
    response = client.post("/api/rules", json=rule_data)
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Missing required field" in payload["error"]


def test_get_rule_by_id(client):
    rule_data = {
        "name": "Fetch Me",
        "action": "allow",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 443,
        "priority": 2,
    }
    create_response = client.post("/api/rules", json=rule_data)
    created = create_response.get_json()["data"]

    get_response = client.get(f"/api/rules/{created['id']}")
    payload = get_response.get_json()

    assert get_response.status_code == 200
    assert payload["data"]["id"] == created["id"]
    assert payload["data"]["dst_port"] == 443


def test_delete_rule(client):
    rule_data = {
        "name": "Delete Me",
        "action": "deny",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 22,
        "priority": 1,
    }
    created = client.post("/api/rules", json=rule_data).get_json()["data"]

    response = client.delete(f"/api/rules/{created['id']}")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert payload["data"]["deleted_rule_id"] == created["id"]


def test_evaluate_packet(client):
    client.post(
        "/api/rules",
        json={
            "name": "Allow HTTP",
            "action": "allow",
            "protocol": "TCP",
            "src_ip": "*",
            "dst_ip": "*",
            "src_port": None,
            "dst_port": 80,
            "priority": 1,
        },
    )

    response = client.post(
        "/api/evaluate",
        json={
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.5",
            "src_port": 5000,
            "dst_port": 80,
            "protocol": "TCP",
            "payload": "test",
        },
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert payload["data"]["action"] == "allow"
    assert payload["data"]["packet"]["dst_port"] == 80


def test_evaluate_batch(client):
    client.post(
        "/api/rules",
        json={
            "name": "Allow Batch",
            "action": "allow",
            "protocol": "TCP",
            "src_ip": "*",
            "dst_ip": "*",
            "src_port": None,
            "dst_port": 80,
            "priority": 1,
        },
    )

    response = client.post(
        "/api/evaluate/batch",
        json=[
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.5",
                "src_port": 5000,
                "dst_port": 80,
                "protocol": "TCP",
            }
            for _ in range(3)
        ],
    )
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert len(payload["data"]["results"]) == 3
    assert payload["data"]["summary"]["allow"] == 3


def test_get_logs(client):
    response = client.get("/api/logs")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert isinstance(payload["data"], list)


def test_get_stats(client):
    client.post(
        "/api/rules",
        json={
            "name": "Stat Rule",
            "action": "allow",
            "protocol": "TCP",
            "src_ip": "*",
            "dst_ip": "*",
            "src_port": None,
            "dst_port": 443,
            "priority": 1,
        },
    )
    client.post(
        "/api/evaluate",
        json={
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.5",
            "src_port": 5000,
            "dst_port": 443,
            "protocol": "TCP",
        },
    )

    response = client.get("/api/stats")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert set(payload["data"].keys()) == {
        "total_rules",
        "total_packets_evaluated",
        "allow_count",
        "deny_count",
        "log_count",
        "avg_eval_time_ms",
    }


def test_input_sanitization(client):
    rule_data = {
        "name": "  <script>alert('x')</script>  ",
        "action": "allow",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 80,
        "priority": 1,
    }
    response = client.post("/api/rules", json=rule_data)
    created = response.get_json()["data"]

    assert created["name"] == "<script>alert('x')</script>"


def test_create_rule_invalid_action(client):
    rule_data = {
        "name": "Bad Action",
        "action": "block",
        "protocol": "TCP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 80,
        "priority": 1,
    }
    response = client.post("/api/rules", json=rule_data)
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Invalid action" in payload["error"]


def test_create_rule_invalid_protocol(client):
    rule_data = {
        "name": "Bad Protocol",
        "action": "deny",
        "protocol": "FTP",
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": None,
        "dst_port": 80,
        "priority": 1,
    }
    response = client.post("/api/rules", json=rule_data)
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Invalid protocol" in payload["error"]


def test_create_rule_invalid_content_type(client):
    response = client.post(
        "/api/rules",
        data="{\"name\": \"Bad\"}",
        content_type="text/plain",
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["error"] == "Content-Type must be application/json"


def test_create_rule_invalid_json(client):
    response = client.post(
        "/api/rules",
        data="{invalid json}",
        content_type="application/json",
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert payload["error"] == "Invalid JSON payload"


def test_evaluate_invalid_json(client):
    response = client.post(
        "/api/evaluate",
        data="{invalid json}",
        content_type="application/json",
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert payload["error"] == "Invalid JSON payload"


def test_sanitize_string_trim_and_invalid_types():
    assert sanitize_string("  hello  ", "name") == "hello"
    with pytest.raises(ValueError, match="name is required"):
        sanitize_string(None, "name")
    with pytest.raises(ValueError, match="name must be a string"):
        sanitize_string(123, "name")
    with pytest.raises(ValueError, match="name must be at most"):
        sanitize_string("x" * 101, "name")


def test_get_int_validation():
    assert get_int("42", "port") == 42
    with pytest.raises(ValueError, match="port must be an integer"):
        get_int("not-int", "port")
    with pytest.raises(ValueError, match="port must be an integer"):
        get_int(True, "port")


def test_get_rule_not_found(client):
    response = client.get("/api/rules/missing-id")
    payload = response.get_json()

    assert response.status_code == 404
    assert payload["status"] == "error"


def test_delete_rule_not_found(client):
    response = client.delete("/api/rules/missing-id")
    payload = response.get_json()

    assert response.status_code == 404
    assert payload["status"] == "error"


def test_evaluate_packet_missing_field(client):
    response = client.post(
        "/api/evaluate",
        json={
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.5",
            "src_port": 5000,
            "dst_port": 80,
        },
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Missing required field" in payload["error"]


def test_evaluate_batch_invalid_item_type(client):
    response = client.post(
        "/api/evaluate/batch",
        json=[
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.5",
                "src_port": 5000,
                "dst_port": 80,
                "protocol": "TCP",
            },
            "not-a-packet",
        ],
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Each packet must be a JSON object" in payload["error"]


def test_evaluate_batch_too_large(client):
    response = client.post(
        "/api/evaluate/batch",
        json=[
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.5",
                "src_port": 5000,
                "dst_port": 80,
                "protocol": "TCP",
            }
            for _ in range(10001)
        ],
    )
    payload = response.get_json()

    assert response.status_code == 400
    assert payload["status"] == "error"
    assert "Batch size must not exceed" in payload["error"]


def test_clear_logs(client):
    response = client.delete("/api/logs")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert payload["data"]["cleared"] is True


def test_create_rule_server_error(client, monkeypatch):
    with client.application.app_context():
        def fail_save(rule):
            raise RuntimeError("database is down")

        monkeypatch.setattr(current_app.db, "save_rule", fail_save)

    response = client.post(
        "/api/rules",
        json={
            "name": "Server Error",
            "action": "allow",
            "protocol": "TCP",
            "src_ip": "*",
            "dst_ip": "*",
            "src_port": None,
            "dst_port": 80,
            "priority": 1,
        },
    )
    payload = response.get_json()

    assert response.status_code == 500
    assert payload["status"] == "error"


def test_delete_rule_server_error(client, monkeypatch):
    response = client.post(
        "/api/rules",
        json={
            "name": "Delete Error",
            "action": "deny",
            "protocol": "TCP",
            "src_ip": "*",
            "dst_ip": "*",
            "src_port": None,
            "dst_port": 80,
            "priority": 1,
        },
    )
    created = response.get_json()["data"]

    with client.application.app_context():
        def fail_delete(rule_id):
            raise RuntimeError("db delete failed")

        monkeypatch.setattr(current_app.db, "delete_rule", fail_delete)

    response = client.delete(f"/api/rules/{created['id']}")
    payload = response.get_json()

    assert response.status_code == 500
    assert payload["status"] == "error"


def test_get_logs_server_error(client, monkeypatch):
    with client.application.app_context():
        def fail_get_audit():
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(current_app.db, "get_audit_log", fail_get_audit)

    response = client.get("/api/logs")
    payload = response.get_json()

    assert response.status_code == 500
    assert payload["status"] == "error"


def test_clear_logs_server_error(client, monkeypatch):
    with client.application.app_context():
        def fail_clear():
            raise RuntimeError("clear failed")

        monkeypatch.setattr(current_app.db, "clear_audit_log", fail_clear)

    response = client.delete("/api/logs")
    payload = response.get_json()

    assert response.status_code == 500
    assert payload["status"] == "error"


def test_stats_server_error(client, monkeypatch):
    with client.application.app_context():
        monkeypatch.setattr(routes, "get_stats", lambda db, engine: (_ for _ in ()).throw(RuntimeError("stats failed")))

    response = client.get("/api/stats")
    payload = response.get_json()

    assert response.status_code == 500
    assert payload["status"] == "error"


def test_get_stats_empty(client):
    response = client.get("/api/stats")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "success"
    assert payload["data"]["total_rules"] == 0
    assert payload["data"]["total_packets_evaluated"] == 0
    assert payload["data"]["avg_eval_time_ms"] == 0.0
