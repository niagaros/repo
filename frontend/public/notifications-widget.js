(function () {
  "use strict";

  var API = "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default/notifications";

  function getAccountId() {
    if (window.currentAccountId) return window.currentAccountId;
    return new URLSearchParams(location.search).get("account_id") || null;
  }

  function esc(s) {
    return (s == null ? "" : String(s)).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function timeAgo(iso) {
    var diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "u ago";
    return Math.floor(diff / 86400) + "d ago";
  }

  var SEVERITY_COLOR = { P0: "#dc2626", P1: "#ef4444", P2: "#f59e0b", P3: "#3b82f6", P4: "#9ca3af", P5: "#9ca3af" };

  var css = ""
    + "#nn-widget{position:relative}"
    + "#nn-badge{position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;font-size:9px;font-weight:700;"
    + "min-width:15px;height:15px;border-radius:8px;display:none;align-items:center;justify-content:center;padding:0 3px;"
    + "font-family:'Inter',sans-serif;line-height:1}"
    + "#nn-badge.show{display:flex}"
    + "#nn-panel{position:absolute;top:calc(100% + 8px);right:0;width:360px;max-height:480px;background:#fff;"
    + "border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.18);z-index:9999;"
    + "display:none;flex-direction:column;overflow:hidden;font-family:'Inter',sans-serif;font-size:12.5px;color:#111827}"
    + "#nn-panel.open{display:flex}"
    + "#nn-hdr{padding:12px 14px;border-bottom:1px solid #f0f0f0;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}"
    + "#nn-hdr b{font-size:13px}"
    + "#nn-mark-all{background:none;border:none;color:#4338ca;font-size:11px;font-weight:600;cursor:pointer;font-family:'Inter',sans-serif}"
    + "#nn-list{overflow-y:auto;flex:1}"
    + ".nn-item{display:flex;gap:10px;padding:10px 14px;border-bottom:1px solid #f7f7f7;cursor:pointer;transition:background .1s}"
    + ".nn-item:hover{background:#fafafa}"
    + ".nn-item.unread{background:#f5f3ff}"
    + ".nn-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:5px}"
    + ".nn-body{flex:1;min-width:0}"
    + ".nn-title{font-weight:600;font-size:12px;line-height:1.4}"
    + ".nn-desc{font-size:11px;color:#6b7280;margin-top:2px;line-height:1.4}"
    + ".nn-meta{font-size:10px;color:#9ca3af;margin-top:4px;display:flex;gap:8px;align-items:center}"
    + ".nn-mandatory{font-size:9px;font-weight:700;text-transform:uppercase;color:#dc2626}"
    + "#nn-empty{padding:36px 14px;text-align:center;color:#9ca3af;font-size:12px}";

  var styleEl = document.createElement("style");
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  var bell = document.querySelector(".btn-icon");
  if (!bell || bell.textContent.trim() !== "🔔") return;

  var wrap = document.createElement("div");
  wrap.id = "nn-widget";
  bell.parentNode.insertBefore(wrap, bell);
  wrap.appendChild(bell);

  var badge = document.createElement("span");
  badge.id = "nn-badge";
  wrap.appendChild(badge);

  var panel = document.createElement("div");
  panel.id = "nn-panel";
  panel.innerHTML = ''
    + '<div id="nn-hdr"><b>Notifications</b><button id="nn-mark-all">Mark all read</button></div>'
    + '<div id="nn-list"><div id="nn-empty">Loading…</div></div>';
  wrap.appendChild(panel);

  var list = panel.querySelector("#nn-list");

  bell.style.cursor = "pointer";
  bell.addEventListener("click", function (e) {
    e.stopPropagation();
    var willOpen = !panel.classList.contains("open");
    panel.classList.toggle("open");
    if (willOpen) load();
  });
  document.addEventListener("click", function (e) {
    if (!wrap.contains(e.target)) panel.classList.remove("open");
  });
  panel.querySelector("#nn-mark-all").addEventListener("click", function (e) {
    e.stopPropagation();
    var accountId = getAccountId();
    if (!accountId) return;
    fetch(API, { method: "POST", body: JSON.stringify({ action: "mark_read", cloud_account_id: accountId }) })
      .then(load);
  });

  function render(notifications) {
    if (!notifications.length) {
      list.innerHTML = '<div id="nn-empty">No notifications yet.</div>';
      return;
    }
    list.innerHTML = notifications.map(function (n) {
      var color = SEVERITY_COLOR[n.severity] || "#9ca3af";
      return ''
        + '<div class="nn-item' + (n.read ? '' : ' unread') + '" data-id="' + esc(n.id) + '" data-link="' + esc(n.resource_link || '') + '">'
        + '  <div class="nn-dot" style="background:' + color + '"></div>'
        + '  <div class="nn-body">'
        + '    <div class="nn-title">' + esc(n.title) + '</div>'
        + (n.description ? '    <div class="nn-desc">' + esc(n.description) + '</div>' : '')
        + '    <div class="nn-meta"><span>' + esc(n.severity) + '</span><span>' + esc(n.domain) + '</span>'
        + '      <span>' + timeAgo(n.created_at) + '</span>'
        + (n.mandatory ? '<span class="nn-mandatory">Mandatory</span>' : '')
        + '    </div>'
        + '  </div>'
        + '</div>';
    }).join("");

    list.querySelectorAll(".nn-item").forEach(function (item) {
      item.addEventListener("click", function () {
        var accountId = getAccountId();
        var id = item.getAttribute("data-id");
        var link = item.getAttribute("data-link");
        if (accountId) {
          fetch(API, { method: "POST", body: JSON.stringify({ action: "mark_read", cloud_account_id: accountId, id: id }) });
        }
        if (link) location.href = link;
      });
    });
  }

  function updateBadge(count) {
    if (count > 0) {
      badge.textContent = count > 99 ? "99+" : String(count);
      badge.classList.add("show");
    } else {
      badge.classList.remove("show");
    }
  }

  function load() {
    var accountId = getAccountId();
    if (!accountId) {
      list.innerHTML = '<div id="nn-empty">No account context on this page.</div>';
      return;
    }
    fetch(API + "?cloud_account_id=" + encodeURIComponent(accountId) + "&limit=30")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        render(d.notifications || []);
        updateBadge(d.unread_count || 0);
      })
      .catch(function () {
        list.innerHTML = '<div id="nn-empty">Could not load notifications.</div>';
      });
  }

  function refreshBadgeOnly() {
    var accountId = getAccountId();
    if (!accountId) return;
    fetch(API + "?cloud_account_id=" + encodeURIComponent(accountId) + "&limit=1")
      .then(function (r) { return r.json(); })
      .then(function (d) { updateBadge(d.unread_count || 0); })
      .catch(function () {});
  }

  setTimeout(refreshBadgeOnly, 1000);
  setInterval(refreshBadgeOnly, 60000);
})();
