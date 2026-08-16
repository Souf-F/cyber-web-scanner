"""Flask application entry point for Sentinel."""

import ipaddress
import socket

from flask import Flask, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from scanner import scan_target

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[],
)


def _is_private_target(hostname: str) -> bool:
    """Return True if hostname resolves to a private/loopback/reserved IP."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except Exception:
        return False


@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Trop de requêtes. Maximum 5 analyses par heure par adresse IP."}), 429


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per hour;1 per 15 seconds")
def api_scan():
    target = (request.json or {}).get("target", "").strip()
    if not target:
        return jsonify({"error": "Aucune cible fournie."}), 400

    # Normalise pour extraire le hostname
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    from urllib.parse import urlparse
    hostname = urlparse(target).hostname or ""

    if not hostname:
        return jsonify({"error": "URL invalide."}), 400

    if _is_private_target(hostname):
        return jsonify({"error": "Les adresses IP privées, locales ou réservées ne sont pas autorisées."}), 400

    try:
        return jsonify(scan_target(target))
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=8080)
