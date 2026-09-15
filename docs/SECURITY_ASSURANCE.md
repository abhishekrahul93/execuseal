# Security assurance and certification roadmap

ExecuSeal is not currently certified. This roadmap separates engineering
evidence from organizational certification and regulatory assessment so that
future claims remain precise and independently verifiable.

There is no single certificate that makes a security product “fully secure.”
ISO/IEC 27001 and ISO/IEC 42001 are management-system standards for an
organization. A penetration test evaluates a defined product and deployment
scope. EU legal obligations depend on the product, provider role, intended use,
market, and release model.

## Current assurance level: public pre-alpha

Evidence available today:

- open-source Apache-2.0 code and public threat model
- deterministic default-deny policy enforcement outside the model
- scoped identities, human approvals, signed exact-action tokens, and replay prevention
- privacy-aware audit chains and independently retained signed checkpoints
- PostgreSQL persistence, distributed rate limiting, metrics, and hardened container
- 100 collected automated test cases; four require the PostgreSQL CI service
- 38-case ASB v0.2 synthetic regression benchmark with documented limitations
- safe public sandbox that never executes a real tool

This evidence does not equal certification, independent validation, or a
real-world safety guarantee.

## Gate 1: pilot-ready engineering

Complete before inviting a design partner to a controlled non-production pilot:

- publish supported versions and a security response service-level target
- enable and test GitHub private vulnerability reporting
- automate dependency, secret, static-analysis, and container scanning
- generate an SBOM for every release and sign release artifacts
- document data flow, retention, deletion, backup, and restore behavior
- add end-to-end tests for at least one maintained agent or MCP integration
- run abuse, concurrency, failover, migration, and recovery tests
- define severity, incident-response, key-rotation, and rollback procedures
- record every limitation and residual risk in a release-specific risk register

Exit evidence: green CI, signed release, SBOM, recovery exercise, completed
security checklist, and a pilot report containing measured results.

## Gate 2: independently reviewed beta

Complete before describing the hosted service as suitable for production pilots:

- commission an independent architecture review and scoped penetration test
- remediate critical and high findings; document accepted residual risks
- verify the web/API implementation against an agreed OWASP ASVS level
- run adversarial testing with datasets not written by the detector authors
- test authorization bypass, replay, approval races, tenant isolation, and audit rollback
- establish vulnerability intake, coordinated disclosure, and patch timelines
- perform a privacy and regulatory applicability assessment with qualified counsel

Publish a dated summary that names the tested version, scope, exclusions, test
provider, and remediation status. Do not publish “passed a pentest” without
those boundaries.

## Gate 3: organizational assurance

Certification becomes meaningful only after a legal entity operates a defined
service with people, processes, suppliers, and evidence over time.

| Framework | What it addresses | When it becomes useful |
|---|---|---|
| ISO/IEC 27001:2022 | Organizational information-security management system | Enterprise procurement and repeatable security operations |
| ISO/IEC 42001:2023 | Organizational AI management system | Responsible development or provision of AI-enabled services |
| SOC 2 | Independent attestation over service-organization controls | When US enterprise buyers request it |
| OWASP ASVS | Technical application-security verification requirements | Product security reviews and penetration-test scope |

Only say “certified” after an accredited certification body has issued a valid
certificate for the named organization and scope. Product documentation must
not imply that an organizational certificate proves every deployment or agent
safe.

## Gate 4: EU market and regulatory readiness

Before commercial release in the EU:

- obtain legal classification of ExecuSeal’s role and intended purpose
- assess Cyber Resilience Act obligations for the distributed software and hosted service
- assess EU AI Act duties for the actual provider/deployer role and downstream use cases
- establish vulnerability handling, security updates, technical documentation,
  conformity assessment, and incident reporting where applicable
- map personal-data flows and controller/processor roles before claiming GDPR readiness

The Cyber Resilience Act’s reporting obligations apply from 11 September 2026,
with its main obligations applying from 11 December 2027. Legal interpretation
must be reviewed for the release and business model in force at that time.

## Claim policy

Every public security statement must identify:

1. the exact version or commit
2. the environment and scope tested
3. the dataset and sample size
4. the date and testing party
5. known limitations and unresolved findings

Until the relevant gate is complete, use “designed for,” “supports,” or “tested
against,” not “certified,” “compliant,” “secure,” “unhackable,” or “enterprise-ready.”

## Authoritative starting points

- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [European Commission: Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)

This roadmap is engineering guidance, not legal or certification advice.
