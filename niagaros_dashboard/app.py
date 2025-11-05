from flask import Flask, render_template, abort
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = BASE_DIR / "templates"
STATIC = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(TEMPLATES),   # explicit path
    static_folder=str(STATIC)         # explicit path
)

# --- Dashboard data (kept from your current app) ---
FAKE_WIDGETS = [
    {"title": "Total keys", "value": 0, "footnote": ""},
    {"title": "Active keys", "value": 0, "footnote": ""},
    {"title": "Inactive keys", "value": 0, "footnote": ""},
    {"title": "Outdated keys", "value": 0, "footnote": ""},
]

FAKE_TABLE = [
    {
        "access_key": "AKIAIOSFODNN7EXAMPLE",
        "active": "Yes",
        "date": "2025-11-04 10:30",
        "message": "Key last used to access S3 bucket niagaros-data"
    },
    {
        "access_key": "AKIA6ZVR3D4YEXAMPLE",
        "active": "No",
        "date": "2025-10-28 16:45",
        "message": "Key was deactivated by admin"
    },
    {
        "access_key": "AKIA9ABCD1234EXAMPLE",
        "active": "Yes",
        "date": "2025-11-03 08:15",
        "message": "Key rotated successfully"
    }
]

# ----------------------------
# Routes
# ----------------------------

# Central homepage (Niagaros hub)
@app.route("/")
def home():
    now = datetime.now()
    cards = [
        {"title": "Access Keys", "desc": "View total, active, and inactive IAM keys", "href": "/access-keys"},
        {"title": "Logs", "desc": "CloudWatch / CloudTrail dashboards (coming soon)", "href": "/logs"},
        {"title": "Metrics", "desc": "Service health and app metrics (coming soon)", "href": "/metrics"},
        {"title": "Settings", "desc": "Configure profiles and regions (coming soon)", "href": "/settings"},
    ]
    # Requires templates/home.html
    return render_template("home.html", now=now, active_page="home", cards=cards)

# Access Keys dashboard (uses your existing fake data)
@app.route("/access-keys")
def access_keys():
    now = datetime.now()
    # Requires templates/access_keys.html
    return render_template(
        "access_keys.html",
        now=now,
        active_page="access-keys",
        widgets=FAKE_WIDGETS,
        rows=FAKE_TABLE
    )

# Placeholder pages for future dashboards
@app.route("/logs")
def logs():
    return render_template(
        "placeholder.html",
        now=datetime.now(),
        active_page="logs",
        title="Logs",
        note="CloudWatch / CloudTrail dashboards coming soon."
    )

@app.route("/metrics")
def metrics():
    return render_template(
        "placeholder.html",
        now=datetime.now(),
        active_page="metrics",
        title="Metrics",
        note="Service metrics and charts coming soon."
    )

@app.route("/settings")
def settings():
    return render_template(
        "placeholder.html",
        now=datetime.now(),
        active_page="settings",
        title="Settings",
        note="Profiles, regions, and preferences coming soon."
    )

# Debug route to verify what Flask sees
@app.route("/_debug")
def _debug():
    files = [p.name for p in TEMPLATES.glob("*")]
    return {
        "template_folder": str(TEMPLATES),
        "exists": TEMPLATES.exists(),
        "files_in_templates": files
    }


if __name__ == "__main__":
    app.run(debug=True)

