"""Flask application entry point for the vulnerability analyzer."""

from flask import Flask, jsonify, render_template, request

from scanner import scan_target

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the dashboard page."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run a scan against the submitted target and return JSON results."""
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided."}), 400
    try:
        return jsonify(scan_target(target))
    except Exception as exc:  # noqa: BLE001 - surface any scan failure to the UI
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
