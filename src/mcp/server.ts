import fs from 'node:fs';
import readline from 'node:readline';
import { scanProject } from '../core/scanner.js';
import type { SignedVexBundle } from '../core/types.js';
import { verifyVexBundle } from '../core/vex-compiler.js';

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: 'vexproof_scan_repo',
    description:
      'Scan a local repository path or public GitHub URL, correlate dependencies with live OSV.dev / CISA KEV / EPSS feeds, compute TypeScript AST call-graph reachability, and compile an Ed25519 signed OpenVEX bundle.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPathOrUrl: { type: 'string', description: 'Absolute/relative repo path or https://github.com/org/repo URL' },
        offlineOnly: { type: 'boolean', description: 'Optional: restrict lookups to cached intel snapshots' },
      },
      required: ['targetPathOrUrl'],
    },
  },
  {
    name: 'vexproof_verify_vex',
    description:
      'Cryptographically verify an Ed25519 SignedVexBundle JSON file against its canonical SHA-256 digest and public key.',
    inputSchema: {
      type: 'object',
      properties: {
        signedVexPath: { type: 'string', description: 'Path to vex.signed.json' },
      },
      required: ['signedVexPath'],
    },
  },
  {
    name: 'vexproof_patch_plan',
    description:
      'Generate a minimal safe-upgrade patch plan and package.json diff targeting only reachable/uncertain CVEs.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPathOrUrl: { type: 'string' },
      },
      required: ['targetPathOrUrl'],
    },
  },
];

function send(msg: Record<string, unknown>) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

async function handleRequest(req: JsonRpcRequest) {
  if (req.method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id: req.id ?? null,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'vexproof-mcp', version: '1.0.0' },
      },
    });
    return;
  }

  if (req.method === 'notifications/initialized') {
    return;
  }

  if (req.method === 'tools/list') {
    send({
      jsonrpc: '2.0',
      id: req.id ?? null,
      result: { tools: TOOLS },
    });
    return;
  }

  if (req.method === 'tools/call') {
    const name = String(req.params?.name ?? '');
    const args = (req.params?.arguments as Record<string, unknown>) ?? {};

    try {
      if (name === 'vexproof_scan_repo') {
        const report = await scanProject(String(args.targetPathOrUrl ?? '.'), {
          offlineOnly: Boolean(args.offlineOnly),
        });
        send({
          jsonrpc: '2.0',
          id: req.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    project: `${report.projectName}@${report.projectVersion}`,
                    metrics: report.metrics,
                    findings: report.findings.map((f) => ({
                      vulnId: f.vuln.cveId ?? f.vuln.id,
                      package: `${f.vuln.packageName}@${f.vuln.installedVersion}`,
                      status: f.status,
                      craPriority: f.craPriority,
                      rationale: f.rationale,
                      callPath: f.callPath,
                    })),
                    canonicalDigestSha256: report.signedVex.canonicalDigestSha256,
                  },
                  null,
                  2
                ),
              },
            ],
          },
        });
        return;
      }

      if (name === 'vexproof_verify_vex') {
        const raw = fs.readFileSync(String(args.signedVexPath), 'utf8');
        const bundle = JSON.parse(raw) as SignedVexBundle;
        const verdict = verifyVexBundle(bundle);
        send({
          jsonrpc: '2.0',
          id: req.id ?? null,
          result: {
            content: [{ type: 'text', text: JSON.stringify(verdict, null, 2) }],
          },
        });
        return;
      }

      if (name === 'vexproof_patch_plan') {
        const report = await scanProject(String(args.targetPathOrUrl ?? '.'));
        send({
          jsonrpc: '2.0',
          id: req.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: `${report.patchPlan.prMarkdown}\n\n\`\`\`diff\n${report.patchPlan.packageJsonDiff}\n\`\`\``,
              },
            ],
          },
        });
        return;
      }

      throw new Error(`Unknown MCP tool: ${name}`);
    } catch (err) {
      send({
        jsonrpc: '2.0',
        id: req.id ?? null,
        result: {
          isError: true,
          content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
        },
      });
    }
    return;
  }

  if (req.id !== undefined) {
    send({
      jsonrpc: '2.0',
      id: req.id,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    });
  }
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const req = JSON.parse(trimmed) as JsonRpcRequest;
    void handleRequest(req);
  } catch {
    // Ignore malformed stdin line
  }
});
