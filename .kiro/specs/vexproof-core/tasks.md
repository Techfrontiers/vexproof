# VEXProof Implementation Tasks

- [x] **Task 1:** Initialize `.kiro/` steering, EARS specs, hooks, auditor agent, and MCP settings.
- [x] **Task 2:** Implement `src/core/types.ts` and `src/core/sbom-parser.ts` (npm, PyPI, Go lockfiles + CycloneDX 1.5 SBOM).
- [x] **Task 3:** Implement `src/core/threat-intel.ts` (live OSV.dev querybatch + vuln detail, CISA KEV, FIRST EPSS, disk cache).
- [x] **Task 4:** Implement `src/core/vuln-symbols.ts` and `src/core/reachability-ast.ts` (TypeScript Compiler API call-graph + entrypoint BFS + dynamic-eval guard).
- [x] **Task 5:** Implement `src/core/vex-compiler.ts` (OpenVEX v0.2.0, CycloneDX VEX, Ed25519 keygen/sign/verify) and `src/core/patch-planner.ts`.
- [x] **Task 6:** Implement `src/core/scanner.ts`, `src/cli/index.ts`, `src/mcp/server.ts`, and `src/server/index.ts`.
- [x] **Task 7:** Build `ui/` React Forensic Workbench with live repository scan, interactive call-graph path viewer, OpenVEX tamper-verify test, and minimal patch diff.
- [x] **Task 8:** Create realistic multi-file test repositories under `examples/` (`acme-eu-gateway`, `fintech-worker`, `legacy-dynamic-plugin`) and pass full Vitest E2E + `check:kiro` + build verification.
