# VEXProof Core Requirements (EARS Specification)

## Requirement 1: Multi-Ecosystem SBOM & Lockfile Ingestion
- **WHEN** the user supplies a repository path (or public GitHub URL), **THE SYSTEM SHALL** parse `package-lock.json`, `package.json`, `requirements.txt`, and `go.mod` to extract exact normalized package ecosystems, names, versions, direct/transitive flags, and PURLs (`pkg:npm/...`, `pkg:pypi/...`, `pkg:golang/...`), and emit a CycloneDX 1.5 JSON SBOM.

## Requirement 2: Live Threat Intelligence Correlation
- **WHEN** dependencies are extracted, **THE SYSTEM SHALL** query `OSV.dev` (`/v1/querybatch` + `/v1/vulns/{id}`), cross-reference `CISA KEV` active exploitation status, and fetch `FIRST EPSS` probability scores while preserving explicit `intelSource` provenance (`live` or disk `cache`) and never inventing synthetic CVE IDs.

## Requirement 3: Deterministic AST Call-Graph Reachability
- **WHEN** scanning JS/TS source files inside a repository, **THE SYSTEM SHALL** parse AST nodes via `typescript`, map project entrypoints (HTTP routes, exported handlers, CLI bins, top-level execution), trace intra-project caller-to-callee edges, and classify each CVE into one of three honest states:
  1. `affected` — A concrete static call path reaches a vulnerable symbol (or imported vulnerable package) from an executable entrypoint, returning `file:line:col` provenance and path chain.
  2. `not_affected` — Static analysis proves the package/vulnerable symbols have zero reachable call paths and no dynamic ambiguity covers them (`vulnerable_code_not_in_execute_path`).
  3. `under_investigation` — Dynamic `eval()`, `new Function()`, computed `require(var)`, or dynamic `import(expr)` prevents sound negative proof.

## Requirement 4: Ed25519 Signed OpenVEX & CycloneDX VEX Compilation
- **WHEN** reachability classification completes, **THE SYSTEM SHALL** compile an OpenVEX v0.2.0 (`vex.json`) and CycloneDX 1.5 VEX (`bom-vex.json`), compute a canonical SHA-256 payload digest, sign it using an Ed25519 private key, and provide a `verifyVexBundle()` routine that rejects any 1-byte modification.

## Requirement 5: Minimal Safe-Upgrade Patch Planning
- **WHEN** any CVE is classified `affected` or `under_investigation`, **THE SYSTEM SHALL** resolve the minimum safe patched version from OSV `fixed` events and generate an actionable `package.json` unified diff and upgrade command, excluding proven `not_affected` alerts from emergency blocking.

## Requirement 6: MCP & Workbench Interoperability
- **THE SYSTEM SHALL** expose scanning, verification, and patch planning over both an HTTP API + React Workbench UI and a stdio MCP server registered in `.kiro/settings/mcp.json`.
