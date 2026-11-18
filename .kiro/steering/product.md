# VEXProof — Product Steering

## Problem Origin (Global Innovation Discovery)
Under the **EU Cyber Resilience Act (CRA)** — whose 24-hour active vulnerability reporting obligation took effect **11 September 2026** ahead of full enforcement in **December 2027** — software and connected-product vendors globally face severe triage paralysis. Traditional SBOM scanners emit dozens or hundreds of CVE alerts for transitive or unreferenced library functions (`lodash`, `minimatch`, `ejs`, `serialize-javascript`, etc.), while enterprise reachability tools cost **$15,000+/year** and free trackers like OWASP Dependency-Track lack call-graph reachability proof.

## Core Principle: Zero-Mock Verification & Compilation
VEXProof is **not** a static dashboard or alert aggregator. It is a deterministic **Reachability Compiler & Cryptographic VEX Attestor**:
1. **Real Lockfile & SBOM Ingestion:** Parses `package-lock.json`, `package.json`, `requirements.txt`, `go.mod`, and generates CycloneDX 1.5 SBOMs (`bom.json`).
2. **Real Live Vulnerability Feeds:** Queries **OSV.dev**, **CISA KEV**, and **FIRST EPSS** APIs (no hardcoded fake CVEs).
3. **Deterministic AST Call-Graph Provenance:** Uses the TypeScript Compiler API across JS/TS modules to trace entrypoint -> caller -> external symbol call sites with exact `file:line:col` proof.
4. **Honest Uncertainty Rule:** Whenever dynamic code execution (`eval`, `new Function`, computed `require(expr)`, dynamic `import(expr)`) is present in a file touching or potentially loading a dependency, status MUST be emitted as `under_investigation`, never falsely suppressed as `not_affected`.
5. **Cryptographic Attestation:** Signs compiled OpenVEX v0.2.0 (`vex.json`) and CycloneDX VEX (`bom-vex.json`) bundles with Ed25519 keys so CI/CD gates and EU CRA auditors can verify payload integrity.
