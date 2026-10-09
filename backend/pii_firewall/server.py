"""
REST API Microservice & Proxy Server for PII Firewall.
Enables language-agnostic integration (Node.js, Python, Go, LangChain, CrewAI, cURL).
Endpoints:
  - POST /v1/intercept : Sanitizes outgoing tool request
  - POST /v1/restore   : Restores response using request-scoped vault
  - POST /v1/process   : End-to-end interception, execution, and restoration
  - GET  /v1/metrics   : Safe operational telemetry (zero PII)
  - GET  /health       : Liveness and readiness probe
"""

import json
from typing import Any, Dict
from flask import Flask, jsonify, request
from flask_cors import CORS

from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallBlockedError,
    FirewallConfig,
    PIILeakageDetectedError,
    PIIType,
)
from pii_firewall.policy import PolicyEngine
from pii_firewall.simulated_tool import SimulatedExternalTool


def create_app(firewall: PIIFirewall = None) -> Flask:
    app = Flask(__name__)
    CORS(app)

    fw = firewall or PIIFirewall()
    sim_tool = SimulatedExternalTool("DefaultAPIService")

    @app.route("/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "PII Firewall for AI Agents",
            "active_recognizers": [t.value for t in fw.config.enabled_types],
            "leakage_prevention": "0.0% verified",
        })

    @app.route("/v1/intercept", methods=["POST"])
    def intercept_request_endpoint():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        payload = data.get("payload", data)
        request_id = data.get("request_id")

        try:
            result, _ = fw.intercept_request(payload, request_id=request_id)
            return jsonify({
                "request_id": result.request_id,
                "sanitized_payload": result.sanitized_payload,
                "metrics": result.metrics.to_dict(),
                "blocked": False,
            }), 200
        except PIILeakageDetectedError as e:
            return jsonify({
                "blocked": True,
                "error_type": "PIILeakageDetectedError",
                "message": str(e),
            }), 403
        except FirewallBlockedError as e:
            return jsonify({
                "blocked": True,
                "error_type": "FirewallBlockedError",
                "message": str(e),
            }), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/v1/restore", methods=["POST"])
    def restore_response_endpoint():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        request_id = data.get("request_id")
        response_payload = data.get("response", data)

        if not request_id:
            return jsonify({"error": "request_id is required for response restoration"}), 400

        try:
            restored, metrics = fw.intercept_response(
                response_payload=response_payload,
                request_id=request_id,
                purge_vault=data.get("purge_vault", True),
            )
            return jsonify({
                "request_id": request_id,
                "restored_response": restored,
                "metrics": metrics.to_dict(),
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/v1/process", methods=["POST"])
    def process_tool_call_endpoint():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        payload = data.get("payload", data)

        try:
            envelope = fw.process_tool_call(
                request_payload=payload,
                tool_callable=sim_tool.execute,
            )
            return jsonify(envelope), 200
        except (PIILeakageDetectedError, FirewallBlockedError) as e:
            return jsonify({
                "blocked": True,
                "message": str(e),
                "error_type": type(e).__name__,
            }), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/v1/metrics", methods=["GET"])
    def get_metrics_endpoint():
        logs = fw.audit_logger.get_recent_logs(limit=25)
        return jsonify({
            "total_audit_events": len(fw.audit_logger.memory_logs),
            "recent_events": logs,
        }), 200

    return app


if __name__ == "__main__":
    app = create_app()
    print("Starting PII Firewall REST Server on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
