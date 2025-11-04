from flask import Flask, render_template
from datetime import datetime

app = Flask(__name__)

# --- Fake dashboard data (placeholder) ---
FAKE_WIDGETS = [
    {"title": "Total Events (last hour)", "value": 0, "footnote": "AWS logs not connected yet"},
    {"title": "Errors (last 24h)", "value": 0, "footnote": "Connect CloudWatch to populate"},
    {"title": "Active Services", "value": 0, "footnote": "Sample metric"},
    {"title": "Avg Response (ms)", "value": 0, "footnote": "Sample metric"},
]

FAKE_TABLE = [
    {"time": "—", "service": "—", "level": "—", "message": "AWS log integration coming soon"},
]

@app.route("/")
def index():
    now = datetime.now()
    return render_template("index.html", widgets=FAKE_WIDGETS, rows=FAKE_TABLE, now=now)

if __name__ == "__main__":
    app.run(debug=True)
