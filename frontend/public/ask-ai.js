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

  // Logos: Simple Icons (CC0) for ChatGPT, Claude, Gemini and Perplexity; LobeHub icons (MIT) for Grok and DeepSeek.
  // Shown only to link to each assistant, as in the issue's mock-up.
  var ICONS = {
    chatgpt: { bg: "#10A37F", fg: "#FFFFFF", d: "M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z" },
    claude: { bg: "#D97757", fg: "#FFFFFF", d: "m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z" },
    gemini: { bg: "#FFFFFF", fg: "#4285F4", d: "M11.04 19.32Q12 21.51 12 24q0-2.49.93-4.68.96-2.19 2.58-3.81t3.81-2.55Q21.51 12 24 12q-2.49 0-4.68-.93a12.3 12.3 0 0 1-3.81-2.58 12.3 12.3 0 0 1-2.58-3.81Q12 2.49 12 0q0 2.49-.96 4.68-.93 2.19-2.55 3.81a12.3 12.3 0 0 1-3.81 2.58Q2.49 12 0 12q2.49 0 4.68.96 2.19.93 3.81 2.55t2.55 3.81" },
    perplexity: { bg: "#1F1F1F", fg: "#FFFFFF", d: "M22.3977 7.0896h-2.3106V.0676l-7.5094 6.3542V.1577h-1.1554v6.1966L4.4904 0v7.0896H1.6023v10.3976h2.8882V24l6.932-6.3591v6.2005h1.1554v-6.0469l6.9318 6.1807v-6.4879h2.8882V7.0896zm-3.4657-4.531v4.531h-5.355l5.355-4.531zm-13.2862.0676 4.8691 4.4634H5.6458V2.6262zM2.7576 16.332V8.245h7.8476l-6.1149 6.1147v1.9723H2.7576zm2.8882 5.0404v-3.8852h.0001v-2.6488l5.7763-5.7764v7.0111l-5.7764 5.2993zm12.7086.0248-5.7766-5.1509V9.0618l5.7766 5.7766v6.5588zm2.8882-5.0652h-1.733v-1.9723L13.3948 8.245h7.8478v8.087z" },
    grok: { bg: "#000000", fg: "#FFFFFF", d: "M9.27 15.29l7.978-5.897c.391-.29.95-.177 1.137.272.98 2.369.542 5.215-1.41 7.169-1.951 1.954-4.667 2.382-7.149 1.406l-2.711 1.257c3.889 2.661 8.611 2.003 11.562-.953 2.341-2.344 3.066-5.539 2.388-8.42l.006.007c-.983-4.232.242-5.924 2.75-9.383.06-.082.12-.164.179-.248l-3.301 3.305v-.01L9.267 15.292M7.623 16.723c-2.792-2.67-2.31-6.801.071-9.184 1.761-1.763 4.647-2.483 7.166-1.425l2.705-1.25a7.808 7.808 0 00-1.829-1A8.975 8.975 0 005.984 5.83c-2.533 2.536-3.33 6.436-1.962 9.764 1.022 2.487-.653 4.246-2.34 6.022-.599.63-1.199 1.259-1.682 1.925l7.62-6.815" },
    deepseek: { bg: "#FFFFFF", fg: "#4D6BFE", d: "M23.748 4.482c-.254-.124-.364.113-.512.234-.051.039-.094.09-.137.136-.372.397-.806.657-1.373.626-.829-.046-1.537.214-2.163.848-.133-.782-.575-1.248-1.247-1.548-.352-.156-.708-.311-.955-.65-.172-.241-.219-.51-.305-.774-.055-.16-.11-.323-.293-.35-.2-.031-.278.136-.356.276-.313.572-.434 1.202-.422 1.84.027 1.436.633 2.58 1.838 3.393.137.093.172.187.129.323-.082.28-.18.552-.266.833-.055.179-.137.217-.329.14a5.526 5.526 0 01-1.736-1.18c-.857-.828-1.631-1.742-2.597-2.458a11.365 11.365 0 00-.689-.471c-.985-.957.13-1.743.388-1.836.27-.098.093-.432-.779-.428-.872.004-1.67.295-2.687.684a3.055 3.055 0 01-.465.137 9.597 9.597 0 00-2.883-.102c-1.885.21-3.39 1.102-4.497 2.623C.082 8.606-.231 10.684.152 12.85c.403 2.284 1.569 4.175 3.36 5.653 1.858 1.533 3.997 2.284 6.438 2.14 1.482-.085 3.133-.284 4.994-1.86.47.234.962.327 1.78.397.63.059 1.236-.03 1.705-.128.735-.156.684-.837.419-.961-2.155-1.004-1.682-.595-2.113-.926 1.096-1.296 2.746-2.642 3.392-7.003.05-.347.007-.565 0-.845-.004-.17.035-.237.23-.256a4.173 4.173 0 001.545-.475c1.396-.763 1.96-2.015 2.093-3.517.02-.23-.004-.467-.247-.588zM11.581 18c-2.089-1.642-3.102-2.183-3.52-2.16-.392.024-.321.471-.235.763.09.288.207.486.371.739.114.167.192.416-.113.603-.673.416-1.842-.14-1.897-.167-1.361-.802-2.5-1.86-3.301-3.307-.774-1.393-1.224-2.887-1.298-4.482-.02-.386.093-.522.477-.592a4.696 4.696 0 011.529-.039c2.132.312 3.946 1.265 5.468 2.774.868.86 1.525 1.887 2.202 2.891.72 1.066 1.494 2.082 2.48 2.914.348.292.625.514.891.677-.802.09-2.14.11-3.054-.614zm1-6.44a.306.306 0 01.415-.287.302.302 0 01.2.288.306.306 0 01-.31.307.303.303 0 01-.304-.308zm3.11 1.596c-.2.081-.399.151-.59.16a1.245 1.245 0 01-.798-.254c-.274-.23-.47-.358-.552-.758a1.73 1.73 0 01.016-.588c.07-.327-.008-.537-.239-.727-.187-.156-.426-.199-.688-.199a.559.559 0 01-.254-.078c-.11-.054-.2-.19-.114-.358.028-.054.16-.186.192-.21.356-.202.767-.136 1.146.016.352.144.618.408 1.001.782.391.451.462.576.685.914.176.265.336.537.445.848.067.195-.019.354-.25.452z" }
  };

  var CSS = [
    ".nai{font:inherit;color:inherit;max-width:100%;box-sizing:border-box}",
    ".nai *{box-sizing:border-box}",
    ".nai h3{font-size:.95em;font-weight:500;margin:0 0 .6em;color:inherit;opacity:.85}",
    ".nai .nai-list{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 .6em;padding:0;list-style:none}",
    ".nai a.nai-btn{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:10px;",
    "text-decoration:none;transition:transform .12s ease}",
    ".nai a.nai-btn svg{width:26px;height:26px;display:block}",
    ".nai a.nai-btn:hover{transform:translateY(-2px)}",
    ".nai a.nai-btn:focus-visible,.nai button:focus-visible,.nai summary:focus-visible{outline:2px solid var(--nai-accent,#3b82f6);outline-offset:2px}",
    ".nai .nai-tools{display:flex;flex-wrap:wrap;gap:4px 14px;align-items:center;font-size:.8em;margin:0 0 .4em}",
    ".nai button.nai-copy{background:none;border:0;padding:0;color:inherit;font:inherit;text-decoration:underline;cursor:pointer;opacity:.85}",
    ".nai details summary{cursor:pointer;opacity:.85;text-decoration:underline}",
    ".nai details[open]{flex-basis:100%}",
    ".nai .nai-status{min-height:1.2em;font-size:.8em;margin:0 0 .3em}",
    ".nai p.nai-note{font-size:.72em;opacity:.6;margin:0;line-height:1.45;max-width:520px}",
    ".nai pre{white-space:pre-wrap;word-break:break-word;font:inherit;font-size:.85em;max-height:260px;overflow:auto;",
    "border:1px solid var(--nai-border,rgba(127,127,127,.35));border-radius:8px;padding:10px;margin:.5em 0}"
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
    box.appendChild(el("h3", { id: titleId, title: "Research Niagaros with AI: see how leading AI assistants analyze Niagaros, its cybersecurity platform and its position in the security and compliance market." }, "Ask AI for a summary"));
    var list = el("ul", { "class": "nai-list" });
    var status = el("p", { "class": "nai-status", role: "status", "aria-live": "polite" });

    ASSISTANTS.forEach(function (a) {
      var li = el("li", {});
      var href = a.prefill ? a.prefill(PROMPT) : a.url;
      var link = el("a", {
        "class": "nai-btn", href: href, target: "_blank", rel: "noopener noreferrer",
        "data-assistant": a.id, "data-prefill": a.prefill ? "yes" : "no",
        "aria-label": "Research Niagaros with " + a.name + (a.prefill ? " (opens with the prompt filled in)" : " (copies the prompt, then opens " + a.name + ")")
      });
      var ic = ICONS[a.id];
      link.style.background = ic.bg;
      link.style.color = ic.fg;
      if (ic.bg === "#FFFFFF") link.style.boxShadow = "inset 0 0 0 1px rgba(0,0,0,.08)";
      link.setAttribute("title", a.name);
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("aria-hidden", "true");
      svg.setAttribute("focusable", "false");
      var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", ic.d);
      path.setAttribute("fill", "currentColor");
      if (a.id === "deepseek" || a.id === "grok") path.setAttribute("fill-rule", "evenodd");
      svg.appendChild(path);
      link.appendChild(svg);
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

    var copyBtn = el("button", { type: "button", "class": "nai-copy", "data-assistant": "copy" }, "Copy prompt");
    copyBtn.addEventListener("click", function () {
      copy(PROMPT).then(function () {
        status.textContent = "Prompt copied. Paste it into any AI assistant.";
      }, function () {
        status.textContent = "Copying is blocked in this browser. Use “Show prompt” below and copy it by hand.";
      });
    });
    box.appendChild(list);
    var tools = el("div", { "class": "nai-tools" });
    tools.appendChild(copyBtn);
    var det = el("details", {});
    det.appendChild(el("summary", {}, "Show prompt"));
    det.appendChild(el("pre", { "class": "nai-prompt" }, PROMPT));
    tools.appendChild(det);
    box.appendChild(tools);
    box.appendChild(status);
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
