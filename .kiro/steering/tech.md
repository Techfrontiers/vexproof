# VEXProof — Technical Steering

## Runtime & Stack
- **Language:** TypeScript (strict mode, ESM `NodeNext` for backend/CLI/MCP, React 18 + Vite for Workbench UI)
- **AST & Call Graph:** `typescript` Compiler API (`ts.createSourceFile`) — zero native C++ build friction across Windows, macOS, and Linux CI runners
- **Vulnerability Intelligence:** Live HTTP clients against:
  - `https://api.osv.dev/v1/querybatch` & `/v1/vulns/{id}`
  - `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - `https://api.first.org/data/v1/epss`
- **Cryptography:** Node.js built-in `node:crypto` (`Ed25519` + `SHA-256` canonical JSON digest)
- **Standards Output:** OpenVEX v0.2.0 (`https://openvex.dev/ns/v0.2.0`) & CycloneDX 1.5 JSON
- **Interfaces:**
  1. CLI (`vexproof scan`, `vexproof verify`)
  2. Local HTTP API (`src/server/index.ts`, port `4311`) + Interactive Forensic Workbench UI (`vite`, port `5174`)
  3. Model Context Protocol server (`src/mcp/server.ts`) registered in `.kiro/settings/mcp.json`
- **Testing:** Vitest unit + end-to-end tests against multi-file sample repositories and live/cached OSV verification
