from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Flask

from app.api.routes import api_bp
from app.database.db import Database
from app.engine.firewall import FirewallEngine
from app.models.rule import Rule


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config:
        app.config.update(config)

    db_path = app.config.get("DATABASE_PATH", "firewall.db")
    database = Database(db_path=db_path)
    engine = FirewallEngine()

    for rule_data in database.get_all_rules():
        rule = Rule.from_dict(rule_data)
        engine.add_rule(rule)

    app.db = database
    app.engine = engine
    app.register_blueprint(api_bp)

    return app
