from flask import Flask, render_template, abort
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = BASE_DIR / "templates"
STATIC = BASE_DIR / "static"

app = Flask(
    __name__,
    template_folder=str(TEMPLATES),   # <-- explicit path
    static_folder=str(STATIC)         # <-- explicit path
)

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

@app.route("/")
def index():
    now = datetime.now()
    # Extra safety: if index.html actually isn't there, fail clearly.
    if not (TEMPLATES / "index.html").exists():
        abort(500, "index.html not found in templates folder")
    return render_template("index.html", widgets=FAKE_WIDGETS, rows=FAKE_TABLE, now=now)

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
