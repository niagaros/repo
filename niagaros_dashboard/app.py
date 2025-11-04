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
    {"title": "Total Events (last hour)", "value": 0, "footnote": ""},
    {"title": "Errors (last 24h)", "value": 0, "footnote": ""},
    {"title": "Active Services", "value": 0, "footnote": ""},
    {"title": "Avg Response (ms)", "value": 0, "footnote": ""},
]

FAKE_TABLE = [
    {"Access keys": "—", "Active": "—", "date": "—", "message": "Need attention"},
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
