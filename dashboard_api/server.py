"""Loopback-only HTTP API for the local SOC dashboard."""

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from incident_management import SQLiteIncidentRepository
from incident_management.models import IncidentStatus, SimulatedOutcome
from dashboard_api.service import DashboardDataService


def create_server(database: str, port: int = 8000, security_table_name: str | None = None) -> ThreadingHTTPServer:
    repository = SQLiteIncidentRepository(database)
    table_name = security_table_name or os.environ.get("SENTINELOT_AWS_TABLE")
    aws_table = None
    if table_name:
        import boto3
        aws_table = boto3.resource("dynamodb").Table(table_name)
    data = DashboardDataService(repository, aws_table=aws_table)

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "SentinelOTDashboard/1.0"

        def log_message(self, _format: str, *args: Any) -> None:
            return

        def _send(self, status: int, value: Any) -> None:
            payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 64_000:
                raise ValueError("Request body is too large")
            value = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(value, dict):
                raise ValueError("Request body must be a JSON object")
            return value

        def do_GET(self) -> None:
            route = urlsplit(self.path)
            query = parse_qs(route.query)
            value = lambda key, default="": query.get(key, [default])[0]
            try:
                if route.path == "/api/health":
                    result = {"status": "ok", "mode": "local-only"}
                elif route.path == "/api/overview":
                    result = data.overview()
                elif route.path == "/api/events":
                    result = data.events(limit=min(max(int(value("limit", "100")), 1), 200), search=value("search"))
                elif route.path == "/api/alerts":
                    result = data.alerts(search=value("search"), severity=value("severity"))
                elif route.path == "/api/incidents":
                    result = data.incidents_list(
                        search=value("search"), status=value("status"), severity=value("severity"),
                    )
                elif route.path.startswith("/api/incidents/") and route.path.endswith("/response-playbooks"):
                    incident_id = unquote(route.path.removeprefix("/api/incidents/").removesuffix("/response-playbooks").strip("/"))
                    result = data.response_playbooks(incident_id)
                elif route.path.startswith("/api/incidents/"):
                    incident_id = unquote(route.path.removeprefix("/api/incidents/"))
                    result = data.incident(incident_id)
                    if result is None:
                        self._send(404, {"error": "Incident not found"})
                        return
                elif route.path == "/api/assets":
                    result = data.assets_list(search=value("search"))
                elif route.path == "/api/mitre":
                    result = data.techniques()
                else:
                    self._send(404, {"error": "Endpoint not found"})
                    return
                self._send(200, result)
            except (ValueError, KeyError) as error:
                self._send(400, {"error": str(error)})
            except Exception:
                self._send(500, {"error": "Dashboard API request failed"})

        def do_POST(self) -> None:
            route = urlsplit(self.path).path
            try:
                body = self._body()
                if route.startswith("/api/incidents/") and route.endswith("/status"):
                    incident_id = unquote(route.removeprefix("/api/incidents/").removesuffix("/status").strip("/"))
                    status = IncidentStatus(body.get("status", ""))
                    incident = data.update_incident_status(
                        incident_id, status, actor=str(body.get("actor", "dashboard analyst")),
                        reason=body.get("reason"),
                    )
                    result = incident.model_dump(mode="json")
                elif route.startswith("/api/incidents/") and route.endswith("/notes"):
                    incident_id = unquote(route.removeprefix("/api/incidents/").removesuffix("/notes").strip("/"))
                    incident = data.add_incident_note(
                        incident_id, str(body.get("text", "")),
                        actor=str(body.get("actor", "dashboard analyst")),
                    )
                    result = incident.model_dump(mode="json")
                elif route.startswith("/api/incidents/") and "/responses/" in route:
                    parts = [unquote(part) for part in route.strip("/").split("/")]
                    if len(parts) != 6 or parts[0:2] != ["api", "incidents"] or parts[3] != "responses":
                        self._send(404, {"error": "Endpoint not found"})
                        return
                    incident_id, action_id, operation = parts[2], parts[4], parts[5]
                    analyst = str(body.get("analyst", ""))
                    reason = str(body.get("reason", ""))
                    if operation == "authorize":
                        incident = data.authorize_response(
                            incident_id, action_id, analyst=analyst,
                            authorized=body.get("authorized") is True, reason=reason,
                            outcome=SimulatedOutcome(body.get("simulation_outcome", "SUCCESS")),
                        )
                    elif operation == "cancel":
                        incident = data.cancel_response(incident_id, action_id, analyst=analyst, reason=reason)
                    elif operation == "rollback":
                        incident = data.rollback_response(incident_id, action_id, analyst=analyst, reason=reason)
                    else:
                        self._send(404, {"error": "Endpoint not found"})
                        return
                    result = incident.model_dump(mode="json")
                elif route.startswith("/api/incidents/") and route.endswith("/responses"):
                    incident_id = unquote(route.removeprefix("/api/incidents/").removesuffix("/responses").strip("/"))
                    incident = data.request_response(
                        incident_id, str(body.get("playbook_id", "")),
                        analyst=str(body.get("analyst", "")), reason=str(body.get("reason", "")),
                        target=str(body["target"]) if body.get("target") else None,
                    )
                    result = incident.model_dump(mode="json")
                elif route == "/api/fortigate/demo":
                    result = data.ingest_fortigate_demo()
                else:
                    self._send(404, {"error": "Endpoint not found"})
                    return
                self._send(200, result)
            except KeyError as error:
                self._send(404, {"error": str(error)})
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._send(400, {"error": str(error)})
            except Exception:
                self._send(500, {"error": "Dashboard API request failed"})

    server = ThreadingHTTPServer(("127.0.0.1", port), RequestHandler)
    server.dashboard_repository = repository
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local-only SentinelOT SOC dashboard API")
    parser.add_argument("--db", default=".sentinelot-incidents.sqlite3")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = create_server(args.db, args.port)
    print(f"SentinelOT dashboard API listening on http://127.0.0.1:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.dashboard_repository.close()


if __name__ == "__main__":
    main()
