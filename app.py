from flask import Flask, jsonify, make_response, render_template, request
from flask_cors import CORS
import boto3
from datetime import datetime, timezone

from scanner import calculate_summary, run_all_checks


app = Flask(__name__)
CORS(app)


def _build_session(payload):
	return boto3.Session(
		aws_access_key_id=payload.get("access_key"),
		aws_secret_access_key=payload.get("secret_key"),
		region_name=payload.get("region"),
	)


@app.route("/", methods=["GET"])
def index():
	return render_template("index.html")


@app.route("/connect", methods=["POST"])
def connect():
	payload = request.get_json(silent=True) or {}
	try:
		session = _build_session(payload)
		sts = session.client("sts")
		identity = sts.get_caller_identity()
		return jsonify(
			{
				"success": True,
				"account_id": identity.get("Account"),
				"arn": identity.get("Arn"),
			}
		)
	except Exception as exc:
		return jsonify({"success": False, "error": str(exc)})


@app.route("/scan", methods=["POST"])
def scan():
	payload = request.get_json(silent=True) or {}
	try:
		session = _build_session(payload)
		results = run_all_checks(session)
		summary = calculate_summary(results)
		return jsonify({"success": True, "results": results, "summary": summary})
	except Exception as exc:
		return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/report", methods=["POST"])
def report():
	payload = request.get_json(silent=True) or {}
	results = payload.get("results", [])
	summary = payload.get("summary", {})
	account_id = payload.get("account_id", "Unknown")
	scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
	html = render_template(
		"report.html",
		results=results,
		summary=summary,
		account_id=account_id,
		scan_date=scan_date,
	)
	response = make_response(html)
	response.headers["Content-Type"] = "text/html; charset=utf-8"
	response.headers["Content-Disposition"] = 'attachment; filename="report.html"'
	return response


if __name__ == "__main__":
	app.run(debug=True)
