"""Safe public playground assets for synthetic ExecuSeal demonstrations."""

# Embedded frontend assets are intentionally formatted for browser readability.
# ruff: noqa: E501

from fastapi import Response
from fastapi.responses import HTMLResponse


def playground_page() -> HTMLResponse:
    """Return the public sandbox without embedding credentials or user data."""

    return HTMLResponse(
        content=_PLAYGROUND_PAGE,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Frame-Options": "DENY",
        },
    )


def playground_script() -> Response:
    """Return the dependency-free playground controller."""

    return Response(
        content=_PLAYGROUND_SCRIPT,
        media_type="application/javascript",
        headers={"Content-Security-Policy": "default-src 'none'"},
    )


_PLAYGROUND_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Try ExecuSeal with fixed synthetic AI-agent actions.">
  <meta name="theme-color" content="#06131d">
  <title>ExecuSeal Playground — Test agent actions safely</title>
  <style>
    :root {
      --ink: #06131d;
      --panel: #0c2230;
      --panel-2: #102c3d;
      --line: #294657;
      --text: #f4f8fa;
      --muted: #a9bfca;
      --lime: #b7f34a;
      --cyan: #63dce2;
      --amber: #ffca68;
      --rose: #ff9299;
      --max: 1240px;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      background:
        radial-gradient(circle at 12% 8%, rgba(183, 243, 74, .12), transparent 25%),
        radial-gradient(circle at 88% 88%, rgba(99, 220, 226, .10), transparent 28%),
        var(--ink);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 16px;
      line-height: 1.55;
    }
    body::before {
      position: fixed;
      inset: 0;
      z-index: -1;
      background-image: linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
      background-size: 36px 36px;
      content: "";
      mask-image: linear-gradient(to bottom, black, transparent 85%);
    }
    a { color: inherit; }
    button, a { -webkit-tap-highlight-color: transparent; }
    button:focus-visible, a:focus-visible { outline: 3px solid var(--lime); outline-offset: 3px; }
    .wrap { width: min(calc(100% - 36px), var(--max)); margin-inline: auto; }
    nav { display: flex; align-items: center; justify-content: space-between; min-height: 72px; border-bottom: 1px solid var(--line); }
    .brand { display: flex; align-items: center; gap: 11px; font-weight: 850; text-decoration: none; }
    .mark { display: grid; width: 32px; height: 32px; place-items: center; border-radius: 8px; background: var(--lime); color: var(--ink); font-weight: 950; }
    .nav-links { display: flex; gap: 24px; }
    .nav-links a { color: var(--muted); font-size: .92rem; font-weight: 700; text-decoration: none; }
    .nav-links a:hover { color: var(--text); }
    header { padding: 64px 0 36px; }
    .eyebrow { margin: 0 0 14px; color: var(--lime); font-size: .75rem; font-weight: 900; letter-spacing: .16em; text-transform: uppercase; }
    h1 { max-width: 760px; margin: 0; font-size: clamp(2.6rem, 6vw, 5.2rem); line-height: .98; letter-spacing: -.055em; }
    .lede { max-width: 680px; margin: 22px 0 0; color: var(--muted); font-size: 1.08rem; }
    .privacy { display: inline-flex; gap: 8px; align-items: center; margin-top: 22px; padding: 8px 12px; border: 1px solid var(--line); border-radius: 999px; color: #d1e2e9; font-size: .82rem; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--lime); box-shadow: 0 0 14px var(--lime); }
    .workspace { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(360px, .95fr); gap: 18px; padding-bottom: 76px; }
    .surface { overflow: hidden; border: 1px solid var(--line); border-radius: 18px; background: rgba(12, 34, 48, .92); box-shadow: 0 28px 70px rgba(0, 0, 0, .24); }
    .surface-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 64px; padding: 0 22px; border-bottom: 1px solid var(--line); }
    .surface-head strong { font-size: .92rem; letter-spacing: .04em; }
    .step { color: var(--muted); font-size: .78rem; }
    .scenarios { display: grid; gap: 11px; padding: 18px; }
    .scenario {
      display: grid;
      grid-template-columns: auto 1fr auto;
      align-items: center;
      gap: 14px;
      width: 100%;
      padding: 17px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #0a1d29;
      color: var(--text);
      text-align: left;
      cursor: pointer;
      transition: border-color .15s ease, background .15s ease, transform .15s ease;
    }
    .scenario:hover { border-color: #527084; background: #102938; transform: translateY(-1px); }
    .scenario[aria-pressed="true"] { border-color: var(--lime); background: #142d34; box-shadow: 0 0 0 1px rgba(183, 243, 74, .22); }
    .scenario-icon { display: grid; width: 42px; height: 42px; place-items: center; border: 1px solid #355365; border-radius: 10px; color: var(--cyan); font-weight: 900; }
    .scenario strong, .scenario span { display: block; }
    .scenario span { margin-top: 2px; color: var(--muted); font-size: .84rem; }
    .scenario code { color: var(--text); font-size: .78rem; }
    .run { width: calc(100% - 36px); min-height: 52px; margin: 0 18px 18px; border: 0; border-radius: 10px; background: var(--lime); color: var(--ink); font-size: .96rem; font-weight: 900; cursor: pointer; }
    .run:hover { background: #c8ff62; }
    .run:disabled { opacity: .65; cursor: wait; }
    .result { min-height: 100%; }
    .result-body { display: grid; min-height: 410px; align-content: center; padding: 32px; }
    .empty { text-align: center; }
    .seal { display: grid; width: 108px; height: 108px; margin: 0 auto 24px; place-items: center; border: 1px solid #3c5a6c; border-radius: 50%; background: radial-gradient(circle, #17394a, #0a1d29 68%); color: var(--cyan); font-size: 2rem; font-weight: 950; box-shadow: inset 0 0 30px rgba(99, 220, 226, .08); }
    .empty h2 { margin: 0; font-size: 1.45rem; }
    .empty p { max-width: 360px; margin: 10px auto 0; color: var(--muted); }
    .decision { display: none; }
    .decision.visible { display: block; }
    .decision-top { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 28px; }
    .decision-badge { padding: 7px 11px; border-radius: 7px; font-size: .78rem; font-weight: 950; letter-spacing: .1em; }
    .decision-badge.allow { background: #dfffc0; color: #275c08; }
    .decision-badge.review { background: #ffedbf; color: #7b4c00; }
    .decision-badge.block { background: #ffdce0; color: #a5101a; }
    .score { color: var(--muted); font-size: .84rem; font-weight: 750; }
    .score b { color: var(--text); font-size: 1.05rem; }
    .decision h2 { margin: 0 0 10px; font-size: 1.6rem; line-height: 1.15; }
    .reason { margin: 0; color: var(--muted); }
    .meter { height: 8px; margin: 28px 0; overflow: hidden; border-radius: 999px; background: #06131d; }
    .meter span { display: block; width: 0; height: 100%; border-radius: inherit; background: var(--lime); transition: width .35s ease; }
    .details { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .detail { padding: 13px; border: 1px solid var(--line); border-radius: 10px; background: #0a1d29; }
    .detail span, .detail strong { display: block; }
    .detail span { color: var(--muted); font-size: .72rem; letter-spacing: .08em; text-transform: uppercase; }
    .detail strong { margin-top: 5px; font-size: .9rem; }
    .result-foot { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 16px 22px; border-top: 1px solid var(--line); color: var(--muted); font-size: .8rem; }
    .feedback { color: var(--lime); font-weight: 800; text-decoration: none; }
    .error { color: var(--rose); }
    @media (max-width: 860px) {
      .workspace { grid-template-columns: 1fr; }
      .result-body { min-height: 360px; }
    }
    @media (max-width: 560px) {
      .nav-links a:first-child { display: none; }
      header { padding-top: 44px; }
      .scenario { grid-template-columns: auto 1fr; }
      .scenario code { display: none; }
      .details { grid-template-columns: 1fr; }
      .result-body { padding: 24px; }
      .result-foot { align-items: flex-start; flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) { .scenario, .meter span { transition: none; } }
  </style>
  <script src="/assets/playground.js" defer></script>
</head>
<body>
  <nav class="wrap" aria-label="Primary navigation">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">E</span>ExecuSeal</a>
    <div class="nav-links"><a href="/docs">API docs</a><a href="https://github.com/abhishekrahul93/execuseal">GitHub ↗</a></div>
  </nav>
  <header class="wrap">
    <p class="eyebrow">Safe public sandbox</p>
    <h1>See the decision before the action.</h1>
    <p class="lede">Choose a synthetic AI-agent request. ExecuSeal will evaluate its policy and blast radius without connecting to a real tool or storing action data.</p>
    <div class="privacy"><span class="dot" aria-hidden="true"></span>Fixed fake data · No credentials · No execution</div>
  </header>
  <main class="wrap workspace">
    <section class="surface" aria-labelledby="scenario-title">
      <div class="surface-head"><strong id="scenario-title">Choose an agent action</strong><span class="step">STEP 1 OF 2</span></div>
      <div class="scenarios">
        <button class="scenario" type="button" data-scenario="inventory_read" aria-pressed="true">
          <span class="scenario-icon" aria-hidden="true">R</span><span><strong>Read stock levels</strong><span>Routine internal lookup with no write impact.</span></span><code>inventory.read</code>
        </button>
        <button class="scenario" type="button" data-scenario="inventory_update" aria-pressed="false">
          <span class="scenario-icon" aria-hidden="true">U</span><span><strong>Update warehouse inventory</strong><span>Production change affecting multiple records.</span></span><code>inventory.update</code>
        </button>
        <button class="scenario" type="button" data-scenario="customer_export" aria-pressed="false">
          <span class="scenario-icon" aria-hidden="true">X</span><span><strong>Export customer records</strong><span>Restricted data sent to an external destination.</span></span><code>customers.export</code>
        </button>
      </div>
      <button class="run" id="run-demo" type="button">Evaluate with ExecuSeal</button>
    </section>
    <section class="surface result" aria-labelledby="result-title" aria-live="polite">
      <div class="surface-head"><strong id="result-title">Policy decision</strong><span class="step">STEP 2 OF 2</span></div>
      <div class="result-body">
        <div class="empty" id="empty-state"><div class="seal" aria-hidden="true">E</div><h2>Ready for evaluation</h2><p>Select an action and run the safety checkpoint to see the result.</p></div>
        <div class="decision" id="decision-state">
          <div class="decision-top"><span class="decision-badge" id="decision-badge"></span><span class="score">Blast radius <b id="risk-score">0</b>/100</span></div>
          <h2 id="decision-heading"></h2><p class="reason" id="decision-reason"></p>
          <div class="meter" aria-hidden="true"><span id="risk-meter"></span></div>
          <div class="details"><div class="detail"><span>Policy rule</span><strong id="policy-rule"></strong></div><div class="detail"><span>Real execution</span><strong>Never performed</strong></div></div>
        </div>
      </div>
      <div class="result-foot"><span id="result-note">Synthetic demonstration only</span><a class="feedback" href="https://github.com/abhishekrahul93/execuseal/issues/new?template=feedback.yml">Share feedback ↗</a></div>
    </section>
  </main>
</body>
</html>
"""


_PLAYGROUND_SCRIPT = """'use strict';

const scenarios = document.querySelectorAll('[data-scenario]');
const runButton = document.getElementById('run-demo');
const emptyState = document.getElementById('empty-state');
const decisionState = document.getElementById('decision-state');
const badge = document.getElementById('decision-badge');
const heading = document.getElementById('decision-heading');
const reason = document.getElementById('decision-reason');
const score = document.getElementById('risk-score');
const meter = document.getElementById('risk-meter');
const policyRule = document.getElementById('policy-rule');
const resultNote = document.getElementById('result-note');
let selectedScenario = 'inventory_read';

for (const scenario of scenarios) {
  scenario.addEventListener('click', () => {
    selectedScenario = scenario.dataset.scenario;
    for (const option of scenarios) {
      option.setAttribute('aria-pressed', String(option === scenario));
    }
  });
}

runButton.addEventListener('click', async () => {
  runButton.disabled = true;
  runButton.textContent = 'Evaluating policy…';
  resultNote.classList.remove('error');
  resultNote.textContent = 'Running a synthetic safety check';
  try {
    const response = await fetch('/v1/demo/authorize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scenario_id: selectedScenario}),
    });
    if (!response.ok) {
      throw new Error(response.status === 429 ? 'Demo rate limit reached. Try again shortly.' : 'The demo could not complete.');
    }
    const result = await response.json();
    emptyState.hidden = true;
    decisionState.classList.add('visible');
    badge.className = `decision-badge ${result.action}`;
    badge.textContent = result.action.toUpperCase();
    heading.textContent = result.action === 'allow' ? 'Routine action may continue.' : result.action === 'review' ? 'Human approval is required.' : 'Unsafe action is stopped.';
    reason.textContent = result.reason;
    score.textContent = String(result.blast_radius.score);
    meter.style.width = `${result.blast_radius.score}%`;
    meter.style.background = result.action === 'allow' ? '#b7f34a' : result.action === 'review' ? '#ffca68' : '#ff9299';
    policyRule.textContent = result.policy_rule_id || 'Default deny';
    resultNote.textContent = `Request ${result.request_id.slice(0, 8)} · Nothing was executed`;
  } catch (error) {
    resultNote.classList.add('error');
    resultNote.textContent = error instanceof Error ? error.message : 'The demo could not complete.';
  } finally {
    runButton.disabled = false;
    runButton.textContent = 'Evaluate with ExecuSeal';
  }
});
"""
