from __future__ import annotations

from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, jsonify, request

from app.engine.firewall import FirewallEngine
from app.models.packet import Packet
from app.models.rule import Rule
from app.database.db import Database

api_bp = Blueprint("api", __name__, url_prefix="/api")

MAX_STRING_LENGTH = 100
MAX_BATCH_SIZE = 10000


def json_response(status: str, data: Any = None, error: Optional[str] = None, code: int = 200):
    payload: Dict[str, Any] = {"status": status}
    if error is not None:
        payload["error"] = error
    else:
        payload["data"] = data
    return jsonify(payload), code


def validate_content_type() -> Optional[Dict[str, Any]]:
    if not request.is_json:
        return {"error": "Content-Type must be application/json"}
    return None


def sanitize_string(value: Any, field_name: str, required: bool = True) -> str:
    if value is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    cleaned = value.strip()
    if len(cleaned) > MAX_STRING_LENGTH:
        raise ValueError(f"{field_name} must be at most {MAX_STRING_LENGTH} characters")
    return cleaned


def get_int(value: Any, field_name: str, required: bool = True) -> Optional[int]:
    if value is None:
        if required:
            raise ValueError(f"{field_name} is required")
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    try:
        integer = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be an integer") from None
    return integer


def validate_rule_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    required_fields = ["name", "action", "protocol", "src_ip", "dst_ip", "priority"]
    for field in required_fields:
        if field not in payload:
            raise ValueError(f"Missing required field: {field}")

    return {
        "name": sanitize_string(payload.get("name"), "name"),
        "action": sanitize_string(payload.get("action"), "action"),
        "protocol": sanitize_string(payload.get("protocol"), "protocol"),
        "src_ip": sanitize_string(payload.get("src_ip"), "src_ip"),
        "dst_ip": sanitize_string(payload.get("dst_ip"), "dst_ip"),
        "src_port": get_int(payload.get("src_port"), "src_port", required=False),
        "dst_port": get_int(payload.get("dst_port"), "dst_port", required=False),
        "priority": get_int(payload.get("priority"), "priority"),
    }


def validate_packet_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    required_fields = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    for field in required_fields:
        if field not in payload:
            raise ValueError(f"Missing required field: {field}")

    return {
        "src_ip": sanitize_string(payload.get("src_ip"), "src_ip"),
        "dst_ip": sanitize_string(payload.get("dst_ip"), "dst_ip"),
        "src_port": get_int(payload.get("src_port"), "src_port"),
        "dst_port": get_int(payload.get("dst_port"), "dst_port"),
        "protocol": sanitize_string(payload.get("protocol"), "protocol"),
        "payload": sanitize_string(payload.get("payload"), "payload", required=False) if payload.get("payload") is not None else None,
    }


def get_stats(database: Database, engine: FirewallEngine) -> Dict[str, Any]:
    cursor = database.connection.cursor()
    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_packets,
            SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END) AS allow_count,
            SUM(CASE WHEN action = 'deny' THEN 1 ELSE 0 END) AS deny_count,
            SUM(CASE WHEN action = 'log' THEN 1 ELSE 0 END) AS log_count,
            AVG(eval_time_ms) AS avg_eval_time
        FROM audit_log
        """
    )
    row = cursor.fetchone()
    return {
        "total_rules": len(engine.get_all_rules()),
        "total_packets_evaluated": row["total_packets"] or 0,
        "allow_count": row["allow_count"] or 0,
        "deny_count": row["deny_count"] or 0,
        "log_count": row["log_count"] or 0,
        "avg_eval_time_ms": float(row["avg_eval_time"] or 0.0),
    }


@api_bp.route("/rules", methods=["GET"])
def list_rules() -> Any:
    return json_response("success", [rule.to_dict() for rule in current_app.engine.get_all_rules()])


@api_bp.route("/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id: str) -> Any:
    rule = current_app.engine.get_rule_by_id(rule_id)
    if rule is None:
        return json_response("error", error="Rule not found", code=404)
    return json_response("success", rule.to_dict())


@api_bp.route("/rules", methods=["POST"])
def create_rule() -> Any:
    validation_error = validate_content_type()
    if validation_error:
        return json_response("error", error=validation_error["error"], code=400)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return json_response("error", error="Invalid JSON payload", code=400)

    try:
        data = validate_rule_payload(payload)
        rule = Rule.from_dict(data)
        current_app.db.save_rule(rule)
        current_app.engine.add_rule(rule)
        return json_response("success", rule.to_dict(), code=201)
    except ValueError as exc:
        return json_response("error", error=str(exc), code=400)
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id: str) -> Any:
    rule = current_app.engine.get_rule_by_id(rule_id)
    if rule is None:
        return json_response("error", error="Rule not found", code=404)

    try:
        current_app.engine.remove_rule(rule_id)
        current_app.db.delete_rule(rule_id)
        return json_response("success", {"deleted_rule_id": rule_id})
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/evaluate", methods=["POST"])
def evaluate_single() -> Any:
    validation_error = validate_content_type()
    if validation_error:
        return json_response("error", error=validation_error["error"], code=400)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return json_response("error", error="Invalid JSON payload", code=400)

    try:
        data = validate_packet_payload(payload)
        packet = Packet.from_dict(data)
        result = current_app.engine.evaluate_packet(packet)
        current_app.db.log_packet(result)
        return json_response("success", result)
    except ValueError as exc:
        return json_response("error", error=str(exc), code=400)
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/evaluate/batch", methods=["POST"])
def evaluate_batch() -> Any:
    validation_error = validate_content_type()
    if validation_error:
        return json_response("error", error=validation_error["error"], code=400)

    payload = request.get_json(silent=True)
    if not isinstance(payload, list):
        return json_response("error", error="Expected a JSON array of packet objects", code=400)
    if len(payload) > MAX_BATCH_SIZE:
        return json_response(
            "error",
            error=f"Batch size must not exceed {MAX_BATCH_SIZE}",
            code=400,
        )

    results: List[Dict[str, Any]] = []
    try:
        for packet_data in payload:
            if not isinstance(packet_data, dict):
                raise ValueError("Each packet must be a JSON object")
            data = validate_packet_payload(packet_data)
            packet = Packet.from_dict(data)
            result = current_app.engine.evaluate_packet(packet)
            current_app.db.log_packet(result)
            results.append(result)

        summary = {
            "allow": sum(1 for item in results if item["action"] == "allow"),
            "deny": sum(1 for item in results if item["action"] == "deny"),
            "log": sum(1 for item in results if item["action"] == "log"),
        }
        return json_response("success", {"results": results, "summary": summary})
    except ValueError as exc:
        return json_response("error", error=str(exc), code=400)
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/logs", methods=["GET"])
def get_logs() -> Any:
    try:
        entries = current_app.db.get_audit_log()
        return json_response("success", entries)
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/logs", methods=["DELETE"])
def clear_logs() -> Any:
    try:
        current_app.db.clear_audit_log()
        return json_response("success", {"cleared": True})
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)


@api_bp.route("/stats", methods=["GET"])
def stats() -> Any:
    try:
        statistics = get_stats(current_app.db, current_app.engine)
        return json_response("success", statistics)
    except Exception as exc:
        return json_response("error", error=str(exc), code=500)
