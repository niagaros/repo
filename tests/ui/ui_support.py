import json

ACCOUNT = "cbb94e43-4e42-4fac-997e-8f931131bde7"
CORS = {"access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*"}


class FakeBackend:
    """In-memory stand-in for the two APIs the Notification Settings page talks to.
    Records every POST so tests can assert on exactly what the UI sends."""

    def __init__(self, recipients=None, test_result=None):
        self.recipients = list(recipients or [])
        self.posts = []
        self.test_result = test_result or {"sent": True}

    def _json(self, route, payload, status=200):
        route.fulfill(status=status, content_type="application/json", headers=CORS, body=json.dumps(payload))

    def handle(self, route):
        req = route.request
        url = req.url
        if req.method == "OPTIONS":
            return route.fulfill(status=200, headers=CORS, body="")
        if "get-dashboard-data" in url:
            return self._json(route, {"account_name": "Domits", "accounts": [{"id": ACCOUNT, "name": "Domits"}]})
        if req.method == "GET" and "analytics=1" in url:
            return self._json(route, {"total_notifications": 0, "integration_health": {}})
        if req.method == "GET":
            return self._json(route, {"channels": {}, "preferences": {}, "recipients": self.recipients})
        body = json.loads(req.post_data or "{}")
        self.posts.append(body)
        action = body.get("action")
        if action == "add_recipient":
            rid = f"r{len(self.recipients) + 1}"
            self.recipients.append({"id": rid, "label": body["label"], "domains": body.get("domains") or None,
                                    "notify_email": body.get("notify_email") or None, "sms_number": body.get("sms_number") or None,
                                    "slack_webhook_url": None, "teams_webhook_url": None, "discord_webhook_url": None,
                                    "webhook_url": body.get("webhook_url") or None})
            return self._json(route, {"id": rid})
        if action == "remove_recipient":
            self.recipients = [r for r in self.recipients if r["id"] != body["id"]]
            return self._json(route, {"removed": True})
        if action == "test_channel":
            return self._json(route, self.test_result)
        return self._json(route, {"ok": True})

    def attach(self, page):
        page.route("**/get-dashboard-data**", self.handle)
        page.route("**/default/notifications**", self.handle)
        return self


def open_settings(page, site, backend):
    backend.attach(page)
    page.goto(f"{site}/notification_settings.html?account_id={ACCOUNT}")
    page.wait_for_selector("#v-content:not([hidden])", timeout=15000)
    return backend
