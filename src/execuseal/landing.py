"""Public landing page for the ExecuSeal gateway."""

# Embedded HTML and CSS are intentionally formatted for browser readability.
# ruff: noqa: E501

from fastapi.responses import HTMLResponse


def landing_page() -> HTMLResponse:
    """Return a dependency-free, security-hardened product landing page."""

    response = HTMLResponse(
        content=_LANDING_PAGE,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Frame-Options": "DENY",
        },
    )
    return response


_LANDING_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="ExecuSeal is an open-source policy firewall for AI-agent actions.">
  <meta name="theme-color" content="#071722">
  <title>ExecuSeal — Control AI-agent actions before execution</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #071722;
      --muted: #4b6070;
      --line: #d9e2e7;
      --paper: #f3f7f5;
      --white: #ffffff;
      --lime: #b7f34a;
      --lime-deep: #437b19;
      --amber: #ffca68;
      --rose: #ff8d93;
      --navy-2: #102b3c;
      --max: 1320px;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
      font-size: 16px;
      line-height: 1.6;
    }
    a { color: inherit; }
    a:focus-visible { outline: 3px solid #6fae29; outline-offset: 4px; }
    .wrap { width: min(calc(100% - 40px), var(--max)); margin-inline: auto; }
    .nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 76px;
      border-bottom: 1px solid var(--line);
    }
    .brand { display: inline-flex; align-items: center; gap: 11px; text-decoration: none; }
    .mark {
      display: grid;
      width: 32px;
      height: 32px;
      place-items: center;
      border-radius: 8px;
      background: var(--ink);
      color: var(--lime);
      font-weight: 900;
    }
    .brand-name { font-size: 1.1rem; font-weight: 800; letter-spacing: -.02em; }
    .links { display: flex; align-items: center; gap: 26px; }
    .links a { font-weight: 650; text-decoration: none; }
    .links a:hover { text-decoration: underline; text-underline-offset: 5px; }
    .hero {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1.08fr) minmax(420px, .92fr);
      align-items: center;
      gap: clamp(48px, 6vw, 88px);
      padding-block: clamp(64px, 8vw, 104px);
      isolation: isolate;
    }
    .hero::before {
      position: absolute;
      z-index: -1;
      inset: 22px -34px;
      border: 1px solid #dce7e0;
      border-radius: 32px;
      background:
        linear-gradient(rgba(7, 23, 34, .035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(7, 23, 34, .035) 1px, transparent 1px),
        radial-gradient(circle at 18% 20%, rgba(183, 243, 74, .24), transparent 29%),
        radial-gradient(circle at 82% 76%, rgba(59, 177, 194, .16), transparent 25%),
        rgba(255, 255, 255, .78);
      background-size: 32px 32px, 32px 32px, auto, auto, auto;
      box-shadow: 0 24px 70px rgba(7, 23, 34, .07);
    }
    .eyebrow {
      margin: 0 0 22px;
      font-size: .78rem;
      font-weight: 850;
      letter-spacing: .18em;
      text-transform: uppercase;
    }
    h1 {
      max-width: 780px;
      margin: 0;
      font-size: clamp(3.1rem, 5vw, 4.8rem);
      line-height: .98;
      letter-spacing: -.055em;
    }
    h1 span { display: block; }
    h1 .accent-line {
      position: relative;
      isolation: isolate;
      width: max-content;
      max-width: 100%;
      margin-top: 10px;
      color: var(--lime-deep);
    }
    h1 .accent-line::after {
      position: absolute;
      z-index: -1;
      right: -10px;
      bottom: 3px;
      left: -8px;
      height: 15px;
      border-radius: 999px;
      background: rgba(183, 243, 74, .38);
      content: "";
      transform: rotate(-1deg);
    }
    .lede { max-width: 650px; margin: 30px 0 0; color: var(--muted); font-size: 1.22rem; }
    .actions { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 34px; }
    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 50px;
      padding: 0 21px;
      border: 1px solid var(--ink);
      border-radius: 8px;
      background: var(--ink);
      color: var(--white);
      font-weight: 780;
      text-decoration: none;
    }
    .button:hover { background: var(--navy-2); }
    .button.secondary { background: transparent; color: var(--ink); }
    .button.secondary:hover { background: #e9f0ec; }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 24px;
      color: var(--muted);
      font-size: .82rem;
      font-weight: 720;
    }
    .meta span {
      padding: 6px 10px;
      border: 1px solid #cfddd4;
      border-radius: 999px;
      background: rgba(255, 255, 255, .72);
    }
    .checkpoint {
      position: relative;
      overflow: hidden;
      border: 1px solid #284a5f;
      border-radius: 20px;
      background: linear-gradient(150deg, #071722, #0c2637);
      color: var(--white);
      box-shadow: 0 30px 70px rgba(7, 23, 34, .22), 12px 12px 0 rgba(183, 243, 74, .16);
    }
    .checkpoint::before {
      display: block;
      width: 100%;
      height: 4px;
      background: linear-gradient(90deg, var(--lime), #59d6dc 55%, transparent);
      content: "";
    }
    .checkpoint-head, .checkpoint-foot {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 20px 24px;
      color: #d3e0e7;
      font-size: .76rem;
      font-weight: 750;
      letter-spacing: .11em;
      text-transform: uppercase;
    }
    .checkpoint-head { border-bottom: 1px solid #284153; }
    .checkpoint-foot { background: #153247; }
    .sim { color: var(--lime); }
    .decision { display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 20px; padding: 25px 24px; border-bottom: 1px solid #284153; }
    .decision code { color: #f2f7f9; font-size: .97rem; font-weight: 700; }
    .badge { padding: 5px 9px; border-radius: 5px; font-size: .74rem; font-weight: 900; letter-spacing: .08em; }
    .allow { background: #e9ffd1; color: #346a13; }
    .review { background: #fff0ce; color: #865300; }
    .block { background: #ffe0e2; color: #ad1720; }
    .checkpoint-copy { padding: 25px 24px 27px; color: #d3e0e7; }
    .checkpoint-copy strong { display: block; color: var(--white); font-size: 1.08rem; }
    section { padding-block: 88px; }
    .section-head { display: grid; grid-template-columns: .75fr 1.25fr; gap: 60px; align-items: end; margin-bottom: 42px; }
    h2 { margin: 0; font-size: clamp(2.25rem, 5vw, 4.2rem); line-height: 1; letter-spacing: -.05em; }
    .section-head p { margin: 0; color: var(--muted); font-size: 1.08rem; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
    .card { min-height: 235px; padding: 27px; border: 1px solid var(--line); border-radius: 14px; background: var(--white); }
    .number { color: var(--lime-deep); font-size: .78rem; font-weight: 900; letter-spacing: .12em; }
    h3 { margin: 46px 0 10px; font-size: 1.25rem; line-height: 1.2; }
    .card p { margin: 0; color: var(--muted); }
    .dark { background: var(--ink); color: var(--white); }
    .dark .section-head p { color: #bed0da; }
    .flow { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; overflow: hidden; border: 1px solid #345064; border-radius: 14px; background: #345064; }
    .flow article { min-height: 190px; padding: 24px; background: var(--navy-2); }
    .flow b { display: block; margin-bottom: 40px; color: var(--lime); font-size: .75rem; letter-spacing: .12em; }
    .flow strong { display: block; font-size: 1.1rem; }
    .flow span { display: block; margin-top: 6px; color: #bed0da; font-size: .92rem; }
    .quickstart { display: grid; grid-template-columns: .85fr 1.15fr; gap: 56px; align-items: center; }
    .quickstart p { color: var(--muted); }
    pre { overflow-x: auto; margin: 0; padding: 28px; border-radius: 14px; background: var(--ink); color: #e7f2f7; font-size: .92rem; line-height: 1.8; }
    pre .accent { color: var(--lime); }
    .evidence { display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 32px; padding: 30px; border: 1px solid var(--line); border-radius: 14px; background: #edf5e7; }
    .evidence h3 { margin: 0 0 7px; }
    .evidence p { margin: 0; color: var(--muted); }
    footer { padding-block: 38px; border-top: 1px solid var(--line); }
    .footer { display: flex; justify-content: space-between; gap: 24px; color: var(--muted); font-size: .9rem; }
    .footer a { color: var(--ink); font-weight: 700; }
    @media (max-width: 840px) {
      .links a:not(:last-child) { display: none; }
      .hero, .section-head, .quickstart { grid-template-columns: 1fr; }
      .hero { padding-top: 58px; }
      .hero::before { inset: 12px -16px; border-radius: 24px; }
      .checkpoint { box-shadow: 8px 8px 0 rgba(183, 243, 74, .16); }
      .grid { grid-template-columns: 1fr; }
      .flow { grid-template-columns: 1fr 1fr; }
      .section-head { gap: 20px; }
    }
    @media (max-width: 520px) {
      .wrap { width: min(calc(100% - 28px), var(--max)); }
      .nav { min-height: 66px; }
      h1 { font-size: clamp(2.9rem, 15vw, 4.2rem); }
      h1 .accent-line { width: auto; }
      .lede { font-size: 1.05rem; }
      .actions, .actions .button { width: 100%; }
      .flow { grid-template-columns: 1fr; }
      .evidence, .footer { grid-template-columns: 1fr; display: grid; }
    }
    @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
  </style>
</head>
<body>
  <header class="wrap">
    <nav class="nav" aria-label="Primary navigation">
      <a class="brand" href="/" aria-label="ExecuSeal home">
        <span class="mark" aria-hidden="true">E</span><span class="brand-name">ExecuSeal</span>
      </a>
      <div class="links">
        <a href="/playground">Try demo</a><a href="#benefits">Benefits</a><a href="/docs">Developers</a>
        <a href="https://github.com/abhishekrahul93/execuseal">GitHub ↗</a>
      </div>
    </nav>
  </header>

  <main>
    <div class="wrap hero">
      <div>
        <p class="eyebrow">Open source · agent action security</p>
        <h1><span>Give agents tools.</span><span class="accent-line">Keep control.</span></h1>
        <p class="lede">Inspect what an AI agent wants to do before it touches your systems. Allow routine work, pause sensitive changes, and block actions outside policy.</p>
        <div class="actions">
          <a class="button" href="/playground">Try the live sandbox</a>
          <a class="button secondary" href="/docs">Explore the API</a>
        </div>
        <p class="meta"><span>Pre-alpha</span><span>Apache-2.0</span><span>Model independent</span></p>
      </div>
      <div class="checkpoint" aria-label="Example ExecuSeal policy decisions">
        <div class="checkpoint-head"><span>Execution checkpoint</span><span class="sim">Simulation</span></div>
        <div class="decision"><code>inventory.read</code><span class="badge allow">ALLOW</span></div>
        <div class="decision"><code>inventory.update</code><span class="badge review">REVIEW</span></div>
        <div class="decision"><code>customers.export</code><span class="badge block">BLOCK</span></div>
        <div class="checkpoint-copy"><strong>One decision before the action.</strong> A reason your team can inspect and audit.</div>
        <div class="checkpoint-foot">Agent → policy → verified executor</div>
      </div>
    </div>

    <section id="benefits" aria-labelledby="benefits-title">
      <div class="wrap">
        <div class="section-head"><h2 id="benefits-title">Control that teams can explain.</h2><p>ExecuSeal gives engineering and security teams a deterministic checkpoint between an AI agent and the tools, data, and APIs it can reach.</p></div>
        <div class="grid">
          <article class="card"><span class="number">01 / POLICY</span><h3>Put permissions in code</h3><p>Define allow, review, and block rules for tools, resources, environments, data sensitivity, and blast radius.</p></article>
          <article class="card"><span class="number">02 / APPROVAL</span><h3>Pause high-impact actions</h3><p>Route sensitive operations to a human reviewer without handing the agent unrestricted credentials.</p></article>
          <article class="card"><span class="number">03 / EVIDENCE</span><h3>Retain verifiable decisions</h3><p>Record the action, policy decision, identity, and integrity evidence for incident review and governance.</p></article>
        </div>
      </div>
    </section>

    <section class="dark" aria-labelledby="flow-title">
      <div class="wrap">
        <div class="section-head"><h2 id="flow-title">Before execution, every time.</h2><p>Model output is treated as a request—not permission. ExecuSeal validates identity, evaluates policy, and returns a bounded decision.</p></div>
        <div class="flow">
          <article><b>01</b><strong>Agent requests</strong><span>Tool, operation, resource, and context.</span></article>
          <article><b>02</b><strong>Policy evaluates</strong><span>Scope, sensitivity, impact, and destination.</span></article>
          <article><b>03</b><strong>Decision returns</strong><span>Allow, block, or require approval.</span></article>
          <article><b>04</b><strong>Evidence remains</strong><span>Auditable reason and signed authorization.</span></article>
        </div>
      </div>
    </section>

    <section aria-labelledby="quickstart-title">
      <div class="wrap quickstart">
        <div><p class="eyebrow">Developer first</p><h2 id="quickstart-title">Pilot without changing your model.</h2><p>Call the gateway before executing a tool action. ExecuSeal is model independent and exposes a standard HTTP API.</p><div class="actions"><a class="button" href="/docs">Open interactive docs</a></div></div>
        <pre aria-label="ExecuSeal API request example"><code><span class="accent">curl</span> -X POST https://execuseal.onrender.com/v1/actions/authorize \\
  -H "X-API-Key: $EXECUSEAL_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "context": { "agent_id": "ops-agent", ... },
    "action": { "tool": "inventory_db", ... }
  }'</code></pre>
      </div>
    </section>

    <section aria-labelledby="evidence-title">
      <div class="wrap evidence">
        <div><h3 id="evidence-title">Trust requires evidence—and clear limits.</h3><p>Review the benchmark methodology, threat model, and pre-alpha limitations before evaluating ExecuSeal for your environment.</p></div>
        <div class="actions"><a class="button secondary" href="https://github.com/abhishekrahul93/execuseal/blob/main/BENCHMARK.md">Review evidence</a><a class="button" href="https://github.com/abhishekrahul93/execuseal/issues">Share feedback</a></div>
      </div>
    </section>
  </main>

  <footer><div class="wrap footer"><span>ExecuSeal · Open-source agent action security</span><span><a href="/healthz">Service status</a> · <a href="https://github.com/abhishekrahul93/execuseal/blob/main/SECURITY.md">Security</a></span></div></footer>
</body>
</html>
"""
