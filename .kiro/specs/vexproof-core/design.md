# VEXProof Core Design

## Architecture ("Frankenstein" Synthesis)
VEXProof stitches four distinct engineering layers into one deterministic verification pipeline:

```text
[Target Repo / GitHub URL]
   ├──> sbom-parser.ts ─────────> CycloneDX 1.5 Components + PURLs
   ├──> threat-intel.ts ────────> OSV.dev + CISA KEV + FIRST EPSS
   └──> reachability-ast.ts ────> Entrypoints + Intra-File/Cross-File Call Graph + Dynamic Guards
                                        │
                                        ▼
                            Reachability Correlator
                     (affected / not_affected / under_investigation)
                                   │           │
                                   ▼           ▼
                         vex-compiler.ts    patch-planner.ts
                     (OpenVEX + Ed25519)   (Min Fixed Version Diff)
```

## Key Design Decisions
1. **Curated Symbol Map + Package Fallback:** Real vulnerabilities often affect specific functions (e.g., `lodash.template`, `ejs.render`, `tar.extract`, `jsonwebtoken.verify` with `algorithms` omission, `serialize-javascript` XSS, `minimatch` ReDoS). When the project imports a package and calls its known vulnerable API along an entrypoint path -> `affected` with symbol provenance. When only an unrelated safe API is called (or the package is never imported in runtime source) and no dynamic loader exists -> `not_affected` (`vulnerable_code_not_in_execute_path`). When the vulnerability affects package initialization/any use and is imported on an active path -> `affected`.
2. **Cryptographic Integrity:** Canonical serialization (sorted object keys recursively) ensures deterministic SHA-256 hashing across platforms so Ed25519 verification is bit-for-bit reproducible.
3. **Cache Hygiene:** Live API responses are cached under `.vexproof-cache/` with a 6-hour TTL to protect external public endpoints during repeated demo/CI runs while preserving explicit `intelSource` markers.
