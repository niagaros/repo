(function () {
  "use strict";

  var AGENT_API = "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default/ai-agent";

  function getAccountId() {
    if (window.currentAccountId) return window.currentAccountId;
    return new URLSearchParams(location.search).get("account_id") || null;
  }

  function esc(s) {
    return (s == null ? "" : String(s)).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var css = ""
    + "#niagaros-ai-widget{position:fixed;bottom:22px;right:22px;z-index:9999;font-family:'Inter',sans-serif;font-size:14px}"
    + "#niagaros-ai-bubble{width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#7c3aed,#6d28d9);"
    + "box-shadow:0 8px 24px rgba(109,40,217,.4);display:flex;align-items:center;justify-content:center;cursor:pointer;"
    + "font-size:24px;color:#fff;border:none;animation:niagarosAiFloat 3.5s ease-in-out infinite;transition:transform .15s}"
    + "#niagaros-ai-bubble:hover{transform:scale(1.07)}"
    + "@keyframes niagarosAiFloat{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}"
    + "#niagaros-ai-bubble:hover{animation-play-state:paused}"
    + "#niagaros-ai-panel{position:absolute;bottom:70px;right:0;width:360px;max-width:calc(100vw - 32px);height:520px;"
    + "max-height:calc(100vh - 120px);background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.25);"
    + "display:flex;flex-direction:column;overflow:hidden;opacity:0;transform:translateY(16px) scale(.97);"
    + "pointer-events:none;transition:opacity .22s ease,transform .22s ease}"
    + "#niagaros-ai-panel.open{opacity:1;transform:translateY(0) scale(1);pointer-events:all}"
    + "#niagaros-ai-hdr{background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;padding:14px 16px;"
    + "display:flex;align-items:center;gap:10px;flex-shrink:0}"
    + "#niagaros-ai-hdr b{font-size:13.5px;display:block}"
    + "#niagaros-ai-hdr span{font-size:11px;opacity:.85}"
    + "#niagaros-ai-close{margin-left:auto;background:rgba(255,255,255,.18);border:none;color:#fff;width:24px;height:24px;"
    + "border-radius:6px;cursor:pointer;font-size:13px;line-height:1}"
    + "#niagaros-ai-scroll{flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:12px;background:#fafafa}"
    + "#niagaros-ai-scroll .empty{color:#9ca3af;font-size:12px;text-align:center;padding:24px 8px}"
    + ".nai-row{display:flex;gap:8px;max-width:88%}"
    + ".nai-row.user{align-self:flex-end;flex-direction:row-reverse}"
    + ".nai-av{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0}"
    + ".nai-row.user .nai-av{background:#6d28d9;color:#fff}"
    + ".nai-row.bot .nai-av{background:#f5f3ff;color:#6d28d9}"
    + ".nai-bub{padding:9px 12px;border-radius:11px;font-size:12.5px;line-height:1.5}"
    + ".nai-row.user .nai-bub{background:#6d28d9;color:#fff;border-top-right-radius:3px}"
    + ".nai-row.bot .nai-bub{background:#fff;color:#111827;border:1px solid #eee;border-top-left-radius:3px}"
    + ".nai-typing{display:flex;gap:3px;padding:2px 0}"
    + ".nai-typing span{width:5px;height:5px;border-radius:50%;background:#c4b5fd;animation:naiBounce 1.2s infinite}"
    + ".nai-typing span:nth-child(2){animation-delay:.15s}.nai-typing span:nth-child(3){animation-delay:.3s}"
    + "@keyframes naiBounce{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-4px)}}"
    + "#niagaros-ai-sugg{display:flex;flex-wrap:wrap;gap:6px;padding:0 12px 10px;flex-shrink:0}"
    + ".nai-chip{background:#f3f4f6;border:1px solid #e5e7eb;border-radius:14px;padding:5px 10px;font-size:10.5px;color:#374151;cursor:pointer}"
    + ".nai-chip:hover{background:#ebebeb}"
    + "#niagaros-ai-inputrow{border-top:1px solid #f0f0f0;padding:10px;display:flex;gap:8px;flex-shrink:0;background:#fff}"
    + "#niagaros-ai-input{flex:1;border:1px solid #e5e7eb;border-radius:8px;padding:8px 10px;font-size:12.5px;font-family:'Inter',sans-serif}"
    + "#niagaros-ai-input:focus{outline:none;border-color:#6d28d9}"
    + "#niagaros-ai-send{background:#6d28d9;color:#fff;border:none;border-radius:8px;padding:0 14px;font-size:12px;font-weight:600;cursor:pointer}"
    + "#niagaros-ai-send:disabled{opacity:.5;cursor:not-allowed}";

  var styleEl = document.createElement("style");
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  var html = ""
    + '<div id="niagaros-ai-widget">'
    + '  <div id="niagaros-ai-panel">'
    + '    <div id="niagaros-ai-hdr">'
    + '      <span style="font-size:18px">🤖</span>'
    + '      <div><b>Niagaros AI Agent</b><span>Antwoorden op basis van jullie echte data</span></div>'
    + '      <button id="niagaros-ai-close">✕</button>'
    + "    </div>"
    + '    <div id="niagaros-ai-scroll"><div class="empty">Stel een vraag over jullie risico\'s, compliance, leveranciers of audits.</div></div>'
    + '    <div id="niagaros-ai-sugg">'
    + '      <div class="nai-chip" data-q="Wat zijn onze grootste risico\'s?">Grootste risico\'s?</div>'
    + '      <div class="nai-chip" data-q="Hoe compliant zijn we in totaal?">Compliance overzicht</div>'
    + '      <div class="nai-chip" data-q="Geef een executive summary">Executive summary</div>'
    + "    </div>"
    + '    <div id="niagaros-ai-inputrow">'
    + '      <input id="niagaros-ai-input" placeholder="Stel je vraag…">'
    + '      <button id="niagaros-ai-send">Vraag</button>'
    + "    </div>"
    + "  </div>"
    + '  <button id="niagaros-ai-bubble" title="Niagaros AI Agent">🤖</button>'
    + "</div>";

  var container = document.createElement("div");
  container.innerHTML = html;
  document.body.appendChild(container.firstElementChild);

  var panel = document.getElementById("niagaros-ai-panel");
  var bubble = document.getElementById("niagaros-ai-bubble");
  var scroll = document.getElementById("niagaros-ai-scroll");
  var input = document.getElementById("niagaros-ai-input");
  var sendBtn = document.getElementById("niagaros-ai-send");
  var historyLoaded = false;

  bubble.addEventListener("click", function () {
    var willOpen = !panel.classList.contains("open");
    panel.classList.toggle("open");
    if (willOpen && !historyLoaded) {
      historyLoaded = true;
      loadHistory();
    }
  });
  document.getElementById("niagaros-ai-close").addEventListener("click", function () {
    panel.classList.remove("open");
  });
  document.querySelectorAll(".nai-chip").forEach(function (chip) {
    chip.addEventListener("click", function () { ask(chip.getAttribute("data-q")); });
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter") sendFromInput();
  });
  sendBtn.addEventListener("click", sendFromInput);

  function sendFromInput() {
    var q = input.value.trim();
    if (!q) return;
    input.value = "";
    ask(q);
  }

  function bubbleEl(role, html) {
    var row = document.createElement("div");
    row.className = "nai-row " + role;
    row.innerHTML = '<div class="nai-av">' + (role === "user" ? "🙂" : "🤖") + '</div><div class="nai-bub">' + html + "</div>";
    return row;
  }

  function clearEmpty() {
    var empty = scroll.querySelector(".empty");
    if (empty) empty.remove();
  }

  function loadHistory() {
    var accountId = getAccountId();
    if (!accountId) return;
    fetch(AGENT_API + "?cloud_account_id=" + encodeURIComponent(accountId))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var history = (d.history || []).slice().reverse();
        if (!history.length) return;
        clearEmpty();
        history.forEach(function (h) {
          scroll.appendChild(bubbleEl("user", esc(h.question)));
          scroll.appendChild(bubbleEl("bot", esc(h.answer)));
        });
        scroll.scrollTop = scroll.scrollHeight;
      })
      .catch(function () {});
  }

  function ask(question) {
    var accountId = getAccountId();
    if (!accountId) {
      clearEmpty();
      scroll.appendChild(bubbleEl("bot", "Ik kan geen account vinden op deze pagina. Open de AI Agent vanuit het dashboard."));
      return;
    }
    clearEmpty();
    scroll.appendChild(bubbleEl("user", esc(question)));
    var typingRow = document.createElement("div");
    typingRow.className = "nai-row bot";
    typingRow.innerHTML = '<div class="nai-av">🤖</div><div class="nai-bub"><div class="nai-typing"><span></span><span></span><span></span></div></div>';
    scroll.appendChild(typingRow);
    scroll.scrollTop = scroll.scrollHeight;
    sendBtn.disabled = true;

    var token = "";
    try { token = localStorage.getItem("niagaros_token") || ""; } catch (e) {}

    fetch(AGENT_API, {
      method: "POST",
      headers: token ? { Authorization: "Bearer " + token } : {},
      body: JSON.stringify({
        action: "ask", cloud_account_id: accountId, question: question,
        asked_by: (function () { try { return localStorage.getItem("niagaros_display_name") || "Admin"; } catch (e) { return "Admin"; } })(),
      }),
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        typingRow.remove();
        scroll.appendChild(bubbleEl("bot", esc(d.answer || "Er ging iets mis.")));
        scroll.scrollTop = scroll.scrollHeight;
      })
      .catch(function () {
        typingRow.remove();
        scroll.appendChild(bubbleEl("bot", "Kon de AI Agent-dienst niet bereiken. Probeer het opnieuw."));
        scroll.scrollTop = scroll.scrollHeight;
      })
      .finally(function () { sendBtn.disabled = false; });
  }
})();
