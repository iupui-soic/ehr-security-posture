# Responsible Disclosure & Research Conduct

This project **measures** the public security posture of open-source EHR systems. It
reads public repository metadata and public vulnerability databases and runs standard
security-posture tooling. It is defensive, measurement-only research.

## Hard rules

1. **No exploit code, no proof-of-concept exploits, no malware.** Nothing in this
   repository may exploit a vulnerability in any system.
2. **No new-vulnerability hunting by default.** The latent-vulnerability SAST probe
   (Construct E) is **disabled** (`construct_e_enabled: false` in
   `config/snapshot.yaml`). Do not add SAST/discovery features unless it is explicitly
   enabled by the maintainers.
3. **Aggregate-only if Construct E is ever enabled.** Report counts/densities only.
   Never publish specifics that identify an exploitable, undisclosed weakness in a
   named system.
4. **Public data only.** Respect each API's terms of service. No authenticated access
   to data you do not own (e.g. no Dependabot alerts on third-party repos).

## If a new vulnerability is identified (even incidentally)

1. **Stop** and do not record exploit details in the repo.
2. **Report privately** through the affected project's published security policy /
   coordinated-disclosure channel.
3. **Allow a remediation window** before any mention in the paper.
4. **Publish only after** disclosure norms are satisfied, and only in aggregate.

## Framing

Findings are presented as ecosystem-improvement opportunities. The paper does **not**
publish a ranked "most insecure EHR" claim — for systems holding real patient records,
that ranking is itself a targeting signal.

## Human subjects

No human subjects and no patient data are involved — only source code and project
metadata. IRB review is not expected; confirm with the institution as a courtesy.
