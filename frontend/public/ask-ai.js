/*
 * "Research Niagaros with AI" (issue #297) — a footer section for niagaros.com.
 *
 * Embed (WordPress / Thrive: a Custom HTML element in the footer symbol):
 *   <div data-niagaros-ask-ai></div>
 *   <script src="https://app.niagaros.com/ask-ai.js" defer></script>
 *
 * Renders into every [data-niagaros-ask-ai] element: one standardized research prompt, a button per AI assistant and
 * a "Copy prompt" button. Assistants whose site accepts a prompt in the URL open with it filled in; for the others the
 * prompt is copied first and the assistant opens empty, and the visitor is told to paste it.
 *
 * Privacy: the prompt only names public Niagaros pages. The widget sets no cookies, uses no storage, never reads the
 * clipboard and makes no requests of its own; loading this script is the only request to Niagaros, and a visitor who
 * clicks an assistant sends that fixed public prompt to that assistant. Answers come from third-party assistants,
 * which the section says plainly.
 * Styling inherits the footer's font and colour; override with the CSS variables --nai-accent and --nai-border.
 */
(function () {
  "use strict";

  var PROMPT = [
    "I am evaluating cybersecurity, cloud security and compliance platforms for a modern infrastructure company.",
    "",
    "Research Niagaros using its official website (https://niagaros.com/), publicly accessible product and documentation pages, and its official Trust Center (https://trust.niagaros.com/).",
    "",
    "Provide an independent and evidence-based overview of Niagaros. Evaluate the following areas:",
    "",
    "1. Company Overview: What is Niagaros, who does it serve, and what problems does it solve?",
    "2. Cloud Security: Evaluate its capabilities across CSPM, CIEM, CWPP, CDR, DSPM, UVM and cloud compliance.",
    "3. Code & CI/CD Security: Evaluate IaC scanning, SAST, SCA, SBOM, container security and developer security workflows.",
    "4. AI Security: Evaluate its approach to AI agents, models, MCP servers, tools, guardrails and AI infrastructure security.",
    "5. Compliance & Governance: Evaluate its support for frameworks such as ISO 27001, SOC 2, GDPR, PCI DSS, NIS2, DORA and the EU AI Act.",
    "6. Risk & Remediation: Evaluate vulnerability management, risk prioritization, security findings, automated remediation and verification.",
    "7. Integrations & Architecture: Evaluate cloud providers, development tools, identity providers, security integrations, APIs and extensibility.",
    "8. Trust & Enterprise Readiness: Assess its publicly documented security practices, privacy, governance, auditability and enterprise capabilities.",
    "9. Competitive Analysis: Compare Niagaros with relevant alternatives such as Wiz, Orca Security, Palo Alto Prisma Cloud, Snyk, Vanta, Drata, OneTrust and Aikido Security.",
    "10. Market Positioning: Explain where Niagaros could differentiate and which market segments it is best suited for.",
    "",
    "Research requirements:",
    "- Use publicly available and verifiable information.",
    "- Prioritize official documentation, product pages, technical documentation and Trust Center information.",
    "- Distinguish implemented capabilities from announced, planned or unverified capabilities.",
    "- Do not assume that a framework is certified merely because it is supported or mentioned.",
    "- Identify missing information and limitations.",
    "- Include source links and indicate when information cannot be independently verified.",
    "- Do not invent product features, customer references, certifications, integrations or performance claims.",
    "",
    "Finish with an executive summary, competitive comparison table, strengths, weaknesses, opportunities and recommendations for a company evaluating Niagaros."
  ].join("\n");

  // prefill: the assistant's own URL parameter for a prompt (checked per provider); null = no such parameter, so the
  // prompt is copied and the assistant opens on its start page.
  var ASSISTANTS = [
    { id: "chatgpt", name: "ChatGPT", url: "https://chatgpt.com/", prefill: function (p) { return "https://chatgpt.com/?q=" + encodeURIComponent(p); } },
    { id: "claude", name: "Claude", url: "https://claude.ai/new", prefill: function (p) { return "https://claude.ai/new?q=" + encodeURIComponent(p); } },
    { id: "gemini", name: "Gemini", url: "https://gemini.google.com/app", prefill: null },
    { id: "perplexity", name: "Perplexity", url: "https://www.perplexity.ai/", prefill: function (p) { return "https://www.perplexity.ai/search?q=" + encodeURIComponent(p); } },
    { id: "grok", name: "Grok", url: "https://grok.com/", prefill: function (p) { return "https://grok.com/?q=" + encodeURIComponent(p); } },
    { id: "deepseek", name: "DeepSeek", url: "https://chat.deepseek.com/", prefill: null }
  ];

  var CSS = [
    ".nai{font:inherit;color:inherit;max-width:100%;box-sizing:border-box}",
    ".nai *{box-sizing:border-box}",
    ".nai h3{font-size:1.05em;font-weight:700;margin:0 0 .35em;color:inherit}",
    ".nai p{margin:0 0 .8em;font-size:.9em;line-height:1.5;opacity:.85}",
    ".nai .nai-list{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 .8em;padding:0;list-style:none}",
    ".nai a.nai-btn,.nai button.nai-btn{display:inline-flex;align-items:center;gap:6px;min-height:40px;padding:8px 14px;border-radius:8px;",
    "border:1px solid var(--nai-border,rgba(127,127,127,.45));background:transparent;color:inherit;font:inherit;font-size:.9em;",
    "font-weight:600;text-decoration:none;cursor:pointer;line-height:1.2}",
    ".nai a.nai-btn:hover,.nai button.nai-btn:hover,.nai a.nai-btn:focus-visible,.nai button.nai-btn:focus-visible{border-color:var(--nai-accent,#3b82f6)}",
    ".nai a.nai-btn:focus-visible,.nai button.nai-btn:focus-visible{outline:2px solid var(--nai-accent,#3b82f6);outline-offset:2px}",
    ".nai button.nai-copy{border-color:var(--nai-accent,#3b82f6)}",
    ".nai p.nai-note{font-size:.78em;opacity:.7}",
    ".nai .nai-status{min-height:1.3em;font-size:.82em;margin:0 0 .5em}",
    ".nai details{font-size:.85em;margin:0 0 .6em}.nai summary{cursor:pointer;opacity:.85}",
    ".nai pre{white-space:pre-wrap;word-break:break-word;font:inherit;font-size:.85em;max-height:260px;overflow:auto;",
    "border:1px solid var(--nai-border,rgba(127,127,127,.35));border-radius:8px;padding:10px;margin:.5em 0 0}",
    "@media (max-width:480px){.nai a.nai-btn,.nai button.nai-btn{flex:1 1 calc(50% - 8px);justify-content:center}}"
  ].join("");

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error("copy failed"));
    });
  }

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    for (var k in attrs) { if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]); }
    if (text != null) e.textContent = text;
    return e;
  }

  var count = 0;

  function render(root) {
    if (root.getAttribute("data-nai-ready")) return;
    root.setAttribute("data-nai-ready", "1");
    var titleId;
    do { titleId = "nai-title-" + (++count); } while (document.getElementById(titleId));  // also unique if loaded twice
    var box = el("section", { "class": "nai", "aria-labelledby": titleId });
    box.appendChild(el("h3", { id: titleId }, "Research Niagaros with AI"));
    box.appendChild(el("p", {}, "Discover how leading AI assistants analyze Niagaros, its cybersecurity platform and its position in the security and compliance market."));
    var list = el("ul", { "class": "nai-list" });
    var status = el("p", { "class": "nai-status", role: "status", "aria-live": "polite" });

    ASSISTANTS.forEach(function (a) {
      var li = el("li", {});
      var href = a.prefill ? a.prefill(PROMPT) : a.url;
      var link = el("a", {
        "class": "nai-btn", href: href, target: "_blank", rel: "noopener noreferrer",
        "data-assistant": a.id, "data-prefill": a.prefill ? "yes" : "no",
        "aria-label": "Research Niagaros with " + a.name + (a.prefill ? " (opens with the prompt filled in)" : " (copies the prompt, then opens " + a.name + ")")
      }, a.name);
      if (!a.prefill) {
        var copied = function () { status.textContent = "Prompt copied. Paste it into " + a.name + "."; };
        var failed = function (opened) {
          det.open = true;
          link.setAttribute("data-copy-failed", "1");  // the next click opens the assistant normally
          status.textContent = "Copying is blocked in this browser" + (opened ? "" : ", so " + a.name + " was not opened") +
            ". Copy the prompt below, then " + (opened ? "paste it into " : "click ") + a.name + (opened ? "." : " again to open it.");
        };
        link.addEventListener("click", function (ev) {
          // No prompt parameter at this assistant: copy first (started inside the click, so the browser allows it),
          // and only open the assistant once the prompt is really on the clipboard. If copying fails the visitor
          // stays here, where the prompt is shown to copy by hand; a second click then opens the assistant.
          if (link.getAttribute("data-copy-failed")) return;
          if (ev.ctrlKey || ev.metaKey || ev.shiftKey) {  // the browser opens its own tab: copy alongside it
            copy(PROMPT).then(copied, function () { failed(true); });
            return;
          }
          ev.preventDefault();
          copy(PROMPT).then(function () {
            copied();
            window.open(a.url, "_blank", "noopener,noreferrer");
          }, function () { failed(false); });
        });
        link.addEventListener("auxclick", function (ev) {  // middle click opens a tab without a click event
          if (ev.button === 1) copy(PROMPT).then(copied, function () { failed(true); });
        });
      }
      li.appendChild(link);
      list.appendChild(li);
    });

    var cli = el("li", {});
    var copyBtn = el("button", { type: "button", "class": "nai-btn nai-copy", "data-assistant": "copy" }, "Copy prompt");
    copyBtn.addEventListener("click", function () {
      copy(PROMPT).then(function () {
        status.textContent = "Prompt copied. Paste it into any AI assistant.";
      }, function () {
        status.textContent = "Copying is blocked in this browser. Use “Show prompt” below and copy it by hand.";
      });
    });
    cli.appendChild(copyBtn);
    list.appendChild(cli);

    box.appendChild(list);
    box.appendChild(status);
    var det = el("details", {});
    det.appendChild(el("summary", {}, "Show prompt"));
    det.appendChild(el("pre", { "class": "nai-prompt" }, PROMPT));
    box.appendChild(det);
    box.appendChild(el("p", { "class": "nai-note" },
      "Answers are generated by third-party AI assistants, not by Niagaros. They may be incomplete or wrong and are not an official Niagaros assessment. Niagaros does not control or endorse them."));
    root.appendChild(box);
  }

  function init() {
    if (!document.getElementById("nai-style")) {
      var st = el("style", { id: "nai-style" });
      st.textContent = CSS;
      (document.head || document.documentElement).appendChild(st);
    }
    var roots = document.querySelectorAll("[data-niagaros-ask-ai]");
    for (var i = 0; i < roots.length; i++) render(roots[i]);
  }

  window.NiagarosAskAI = { prompt: PROMPT, assistants: ASSISTANTS.map(function (a) { return { id: a.id, name: a.name, url: a.url, prefill: !!a.prefill }; }), init: init };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
