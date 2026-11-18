# Devpost Submission Copy — VEXProof (Kiroween 2026)

## Project Title
VEXProof — Reachability-Verified SBOM & Ed25519 Signed OpenVEX Compiler

## Elevator Pitch (<= 200 chars)
Turn noisy SBOM CVE lists into Ed25519-signed OpenVEX compliance proof using deterministic TypeScript AST call-graph reachability and live OSV.dev, CISA KEV & EPSS intelligence.

## Category
**Frankenstein** *(Stitching together Compiler AST Call-Graphs, Live OSV/KEV/EPSS Threat Intelligence, Ed25519 OpenVEX Cryptography, and Automated Minimal Patch PRs)*

## Built With
TypeScript, Node.js, React, Vite, Express, CycloneDX 1.5, OpenVEX v0.2.0, OSV.dev API, CISA KEV, FIRST EPSS, Ed25519, Model Context Protocol (MCP), Kiro Specs & Hooks

## What It Does
Under the **EU Cyber Resilience Act (CRA)** (whose 24-hour active vulnerability reporting obligation began in September 2026 ahead of December 2027 enforcement), software teams waste countless engineering hours triaging transitive or unreached CVEs flagged by traditional SBOM tools.

VEXProof replaces static vulnerability dashboards with a zero-mock **Verification & Compilation Engine**:
1. **Parses real lockfiles & manifests** (`package-lock.json`, `package.json`, `requirements.txt`, `go.mod`) into a CycloneDX 1.5 SBOM.
2. **Fetches live threat telemetry** from `OSV.dev`, `CISA KEV`, and `FIRST EPSS`.
3. **Constructs an intra-project AST Call-Graph** via the TypeScript Compiler API from runtime entrypoints down to exact external symbol call sites (`file:line:col`) — proving whether a CVE (`lodash.template`, `ejs.render`, etc.) is actually `affected` or `not_affected` (`vulnerable_code_not_in_execute_path`), while honestly gating dynamic `eval()` / computed `require()` patterns as `under_investigation`.
4. **Compiles & signs OpenVEX v0.2.0 (`vex.json`)** using canonical SHA-256 + Ed25519 signatures with live 1-byte tamper detection.
5. **Generates minimal safe-upgrade PRs** targeting only genuinely reachable dependencies.

## 3-Minute Video Demo Script (Checklist for Recording)
- **0:00 – 0:30 (Problem):** Show `examples/acme-eu-gateway/package-lock.json` and explain how traditional SBOM scanners flag all 5 libraries uniformly under EU CRA pressure.
- **0:30 – 1:15 (Kiro Integration):** Show `.kiro/steering/`, `.kiro/specs/vexproof-core/`, `.kiro/hooks/test-on-save.json`, `.kiro/hooks/kiroween-guard.json`, and `.kiro/settings/mcp.json` running the native `vexproof` MCP server.
- **1:15 – 2:20 (Live Workbench Demo):** Run VEXProof Workbench on `acme-eu-gateway` -> watch live OSV.dev + AST prove `lodash.template` & `ejs.render` as **Affected** (with exact `src/renderer.ts` line evidence) while suppressing dead `serialize-javascript` & unimported `minimatch` as **Not Affected** -> scan `fintech-worker` (`_.chunk` safe usage = 100% suppression) -> scan `legacy-dynamic-plugin` (honest `under_investigation`).
- **2:20 – 3:00 (Tamper Test & Minimal PR):** Click **"Tamper 1 Statement"** -> click **"Verify Ed25519 Signature"** to show instant SHA-256 tamper rejection -> open **"Minimal Upgrade PR"** tab & finish.
