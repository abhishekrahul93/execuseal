# ExecuSeal public launch kit

Use this material for an honest pre-alpha launch. Update the measured figures
only after rerunning the linked commit and benchmark.

## One-sentence explanation

ExecuSeal is an open-source checkpoint that lets an AI agent request a tool
action, then allows, blocks, or pauses it for human approval before execution.

## LinkedIn launch draft

I built ExecuSeal, an open-source action firewall for AI agents.

AI agents can now call databases, APIs, files, email, browsers, and MCP tools.
The difficult question is no longer only “What did the model say?” It is “What
is the agent allowed to do before it affects a real system?”

ExecuSeal creates a control point before execution:

- routine actions can be allowed
- high-impact changes can require human review
- unauthorized or risky actions can be blocked by default
- decisions include an explainable policy reason and blast-radius score
- exact-action tokens, replay prevention, scoped identities, and audit evidence
  support enforcement outside the model

The public sandbox uses fixed synthetic actions and never executes a real tool.
The project currently collects 100 automated test cases (96 pass in the local
suite and 4 PostgreSQL cases run in the dedicated CI job), plus a 91.3 F1
regression baseline on the small 38-case ASB v0.2 synthetic benchmark.

ExecuSeal is pre-alpha—not a certified product or a guarantee that an AI system
is safe. I am sharing it now to learn from AI engineers, security teams, and
platform teams building tool-using agents.

Try the sandbox: https://execuseal.onrender.com/playground

GitHub: https://github.com/abhishekrahul93/execuseal

I would value feedback on integrations, policy design, false positives, and the
approval workflow. Please use only synthetic or fully redacted examples.

#AISafety #AIAgents #CyberSecurity #OpenSource #Python #FastAPI

## Demo script (60–90 seconds)

1. State the problem: agents can cause real actions, not just generate text.
2. Open the sandbox and run **Read stock levels**; show `ALLOW`.
3. Run **Update warehouse inventory**; show `REVIEW`.
4. Run **Export customer records**; show `BLOCK`.
5. Point out the policy rule, blast-radius score, and “Never performed” label.
6. End with the limitation: synthetic demo, no real tool execution, pre-alpha.
7. Invite a narrow response: “Which agent framework should I integrate first?”

## Claims checklist

Safe to say:

- open source under Apache-2.0
- model independent
- public synthetic sandbox
- 100 collected automated test cases, after the linked CI run is green
- 91.3 F1 on the 38-case ASB v0.2 synthetic regression benchmark

Do not say:

- certified, unhackable, enterprise-ready, or fully production-ready
- 91.3% real-world protection or attack prevention
- proven at scale or trusted by customers without verifiable evidence
- GDPR-, EU AI Act-, ISO 27001-, ISO 42001-, or SOC 2-compliant

## Feedback routes

- product feedback: GitHub feedback issue using synthetic or redacted data
- defects: GitHub bug report using a synthetic reproduction
- vulnerabilities: GitHub private vulnerability reporting, never a public issue
