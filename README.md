# VEXProof — Reachability-Verified SBOM & Ed25519 Signed OpenVEX Compiler

> **Kiroween 2026 Submission • Category: `Frankenstein`**
> Stitching together **TypeScript AST Call-Graph Analysis**, **Live OSV.dev / CISA KEV / FIRST EPSS Feeds**, **Ed25519 Cryptographic OpenVEX Attestation**, and **Minimal Upgrade PR Generation** into one deterministic EU Cyber Resilience Act (CRA) compliance compiler.

---

## Why VEXProof Exists (Problem-First Global Discovery)

Software teams globally face an imminent regulatory & operational cliff:
- Under the **EU Cyber Resilience Act (CRA)** (24-hour active vulnerability notification started **September 2026**, full enforcement **December 2027**), software and connected-device vendors must prove which disclosed CVEs actually impact shipped code.
- Traditional free scanners (like OWASP Dependency-Track) flood engineers with transitive and dead-code CVE alerts because they lack a **Call-Graph Reachability Engine**, while enterprise alternatives cost **\$15,000+/year**.

VEXProof replaces noisy CVE alert dashboards with a verifiable **Reachability & Cryptographic VEX Compiler**:
1. **Real Lockfile & CycloneDX 1.5 SBOM Parser:** Ingests `package-lock.json`, `package.json`, `requirements.txt`, and `go.mod` (`src/core/sbom-parser.ts`).
2. **Real Live Vulnerability Intelligence:** Queries `api.osv.dev/v1/querybatch`, `api.osv.dev/v1/vulns/{id}`, `CISA KEV`, and `FIRST EPSS` — zero fabricated CVE data (`src/core/threat-intel.ts`).
3. **Deterministic AST Call-Graph Provenance:** Builds intra-project call paths from runtime entrypoints (`src/core/reachability-ast.ts`) to distinguish:
   - `affected`: Executable call path reaches a vulnerable symbol (`file:line:col` + path chain).
   - `not_affected` (`vulnerable_code_not_in_execute_path`): Dead/uncalled helper or safe API subset (e.g., `lodash.chunk` instead of `lodash.template`) with zero dynamic hazards.
   - `under_investigation`: Honest soundness guard triggered whenever `eval()`, `new Function()`, or computed `require(var)` blocks negative proof.
4. **Ed25519 Signed OpenVEX v0.2.0 & CycloneDX VEX:** Canonical SHA-256 digest + Ed25519 signature + live tamper verification (`src/core/vex-compiler.ts`).
5. **Minimal Safe-Upgrade PR Planner:** Computes exact minimum patched versions only for reachable CVEs (`src/core/patch-planner.ts`).

---

## Architecture (`Frankenstein` Synthesis)

```text
[Local Repo or GitHub URL]
   ├──> sbom-parser.ts ─────────> CycloneDX 1.5 SBOM (bom.json)
   ├──> threat-intel.ts ────────> Live OSV.dev + CISA KEV + FIRST EPSS
   └──> reachability-ast.ts ────> TypeScript Compiler AST + Entrypoint BFS + Dynamic Eval Guard
                                        │
                                        ▼
                                 correlator.ts
                   (affected / not_affected / under_investigation)
                                   │           │
                                   ▼           ▼
                         vex-compiler.ts    patch-planner.ts
                    (OpenVEX + Ed25519)    (Minimal package.json PR)
```

---

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Real End-to-End Tests (Includes Live OSV.dev Integration & Tamper Proof)
```bash
npm test
npm run check:kiro
```

### 3. Run the CLI Against Real Sample Repositories (or Your Own Repo / GitHub URL)
```bash
npm run cli -- demo-real --out .vexproof-out
npm run cli -- verify .vexproof-out/vex.signed.json --pub .vexproof-out/vexproof.pub
```

### 4. Launch the Forensic Workbench UI + API
```bash
npm run dev
```
- **Frontend Workbench:** `http://localhost:5174`
- **Forensic API:** `http://localhost:4311/api/health`

---

## How Kiro Was Used (`.kiro/` Directory)

All `.kiro/` configuration files are intentionally tracked in this public repository per Kiroween 2026 rules:
- `.kiro/steering/` (`product.md`, `tech.md`, `structure.md`): Anchors EU CRA problem provenance and zero-mock engineering invariants.
- `.kiro/specs/vexproof-core/` (`requirements.md`, `design.md`, `tasks.md`): EARS formal requirements, architecture design, and task breakdown driving the codebase.
- `.kiro/hooks/` (`test-on-save.json`, `kiroween-guard.json`): Automatically runs Vitest on core edits and prevents `.kiro/` from ever being `.gitignore`d.
- `.kiro/agents/vex-auditor.json` & `.kiro/settings/mcp.json`: Exposes VEXProof's own stdio MCP server (`src/mcp/server.ts`) directly inside Kiro (`vexproof_scan_repo`, `vexproof_verify_vex`, `vexproof_patch_plan`).

---

## License
MIT License — see [LICENSE](./LICENSE).
