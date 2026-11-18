# VEXProof — Repository Structure Steering

```text
vexproof/
├── .kiro/                      # Kiro Specs, Steering, Hooks, Agents & MCP config (MUST remain tracked)
├── src/
│   ├── core/                   # Deterministic SBOM, Intel, AST Call-Graph, OpenVEX Signer, Patch Planner
│   ├── cli/                    # CLI entrypoints (`scan`, `verify`, `demo-real`)
│   ├── mcp/                    # Stdio JSON-RPC MCP server exposing VEXProof tools to Kiro
│   └── server/                 # Express API driving the Forensic Workbench UI
├── ui/                         # React + Vite Interactive Reachability & OpenVEX Workbench
├── examples/                   # Realistic multi-file sample projects with real lockfiles & CVEs
├── scripts/                    # Compliance checks (`check-kiro-compliance.mjs`)
└── tests/                      # Vitest test suite verifying AST reachability, Ed25519 crypto & CLI/API
```

## Non-Negotiable Invariants
- Never add `.kiro/` to `.gitignore`.
- Never mark a CVE as `not_affected` if dynamic `eval`/`require(var)` ambiguity exists on the target package or module.
- Never fabricate vulnerability IDs or EPSS scores; always tag telemetry provenance (`live` vs `cache` vs `offline-snapshot`).
