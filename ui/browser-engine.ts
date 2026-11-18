import { correlateReachabilityFindings } from '../src/core/correlator';
import { buildPatchPlan } from '../src/core/patch-planner';
import type { AnalyzedProjectGraph } from '../src/core/reachability-ast';
import type {
  CallGraphEdge,
  CallGraphNode,
  CallSite,
  CycloneDxSbom,
  DynamicHazard,
  OpenVexDocument,
  ParsedDependency,
  ScanReport,
  SignedVexBundle,
  VulnerabilityIntel,
} from '../src/core/types';

export interface VirtualRepo {
  id: string;
  name: string;
  description: string;
  files: Record<string, string>;
}

export const BUILTIN_SAMPLE_REPOS: Record<string, VirtualRepo> = {
  'examples/acme-eu-gateway': {
    id: 'acme-eu-gateway',
    name: 'acme-eu-gateway',
    description:
      'EU B2B Payment & Invoice Gateway with real mixed reachable/unreachable CVEs (OSV.dev live target)',
    files: {
      'package.json': JSON.stringify(
        {
          name: 'acme-eu-gateway',
          version: '2.4.1',
          description:
            'EU B2B Payment & Invoice Gateway with real mixed reachable/unreachable CVEs (OSV.dev live target)',
          main: 'src/server.ts',
          dependencies: {
            ejs: '3.1.9',
            jsonwebtoken: '8.5.1',
            lodash: '4.17.20',
            minimatch: '3.0.4',
            'serialize-javascript': '3.1.0',
          },
        },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'acme-eu-gateway',
          version: '2.4.1',
          lockfileVersion: 3,
          requires: true,
          packages: {
            '': {
              name: 'acme-eu-gateway',
              version: '2.4.1',
              dependencies: {
                ejs: '3.1.9',
                jsonwebtoken: '8.5.1',
                lodash: '4.17.20',
                minimatch: '3.0.4',
                'serialize-javascript': '3.1.0',
              },
            },
            'node_modules/ejs': { version: '3.1.9' },
            'node_modules/jsonwebtoken': { version: '8.5.1' },
            'node_modules/lodash': { version: '4.17.20' },
            'node_modules/minimatch': { version: '3.0.4' },
            'node_modules/serialize-javascript': { version: '3.1.0' },
          },
        },
        null,
        2
      ),
      'src/server.ts': `import { verifyMerchantToken } from './auth';
import { renderCustomerInvoice } from './renderer';

interface MockApp {
  post: (path: string, handler: (req: { body: Record<string, string>; headers: Record<string, string> }) => string) => void;
}

export function bootstrapGateway(app: MockApp) {
  app.post('/api/v1/invoice/preview', (req) => {
    const claims = verifyMerchantToken(req.headers.authorization ?? '');
    return renderCustomerInvoice(req.body.templateSource ?? '<h1><%= total %></h1>', {
      merchant: claims.sub,
      total: req.body.total ?? '0.00 EUR',
    });
  });
}
`,
      'src/renderer.ts': `import _ from 'lodash';
import ejs from 'ejs';

export function renderCustomerInvoice(rawTemplate: string, data: Record<string, unknown>): string {
  // Reachable vulnerable sink 1: lodash.template (CVE-2021-23337)
  const precompiled = _.template(rawTemplate);
  const intermediate = precompiled(data);
  // Reachable vulnerable sink 2: ejs.render (CVE-2024-33883)
  return ejs.render('<section><%- body %></section>', { body: intermediate });
}
`,
      'src/auth.ts': `import { verify } from 'jsonwebtoken';
import serialize from 'serialize-javascript';

export function verifyMerchantToken(token: string): { sub: string } {
  const secret = process.env.JWT_PUBLIC_KEY ?? 'placeholder-demo-key';
  return verify(token, secret) as { sub: string };
}

// Dead internal helper — never called or exported from any reachable runtime entrypoint
function legacyDeadDebugSerializer(payload: unknown): string {
  return serialize(payload);
}
`,
    },
  },
  'examples/fintech-worker': {
    id: 'fintech-worker',
    name: 'fintech-worker',
    description:
      'Clean worker calling only non-vulnerable lodash.chunk with zero dynamic eval -> 100% VEX suppression proof',
    files: {
      'package.json': JSON.stringify(
        {
          name: 'fintech-batch-worker',
          version: '1.2.0',
          main: 'src/index.ts',
          dependencies: {
            lodash: '4.17.20',
            minimatch: '3.0.4',
            'serialize-javascript': '3.1.0',
          },
        },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'fintech-batch-worker',
          version: '1.2.0',
          lockfileVersion: 3,
          packages: {
            'node_modules/lodash': { version: '4.17.20' },
            'node_modules/minimatch': { version: '3.0.4' },
            'node_modules/serialize-javascript': { version: '3.1.0' },
          },
        },
        null,
        2
      ),
      'src/index.ts': `import _ from 'lodash';

export function chunkSettlementBatches<T>(records: T[], batchSize = 50): T[][] {
  // Only invokes safe _.chunk — never touches _.template, _.merge, _.defaultsDeep, _.zipObjectDeep, or _.trim
  return _.chunk(records, batchSize);
}
`,
    },
  },
  'examples/legacy-dynamic-plugin': {
    id: 'legacy-dynamic-plugin',
    name: 'legacy-dynamic-plugin',
    description:
      'Demonstrates VEXProof Soundness Guard: dynamic require() prevents false not_affected suppression',
    files: {
      'package.json': JSON.stringify(
        {
          name: 'legacy-dynamic-plugin',
          version: '0.9.0',
          main: 'src/index.ts',
          dependencies: {
            lodash: '4.17.20',
            minimatch: '3.0.4',
          },
        },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'legacy-dynamic-plugin',
          version: '0.9.0',
          lockfileVersion: 3,
          packages: {
            'node_modules/lodash': { version: '4.17.20' },
            'node_modules/minimatch': { version: '3.0.4' },
          },
        },
        null,
        2
      ),
      'src/index.ts': `export function loadTenantFormatter(moduleName: string): unknown {
  // Dynamic require obscures static call graph — VEXProof MUST flag under_investigation
  return require(moduleName);
}
`,
    },
  },
};

function buildNpmPurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/');
    return `pkg:npm/%40${scope.slice(1)}/${pkg}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

function parseVirtualLockfile(files: Record<string, string>): {
  projectName: string;
  projectVersion: string;
  dependencies: ParsedDependency[];
  rawPackageJson: Record<string, unknown> | null;
} {
  const rawPkg = files['package.json'] ? (JSON.parse(files['package.json']) as Record<string, unknown>) : null;
  const projectName = (rawPkg?.name as string) || 'custom-sandbox-repo';
  const projectVersion = (rawPkg?.version as string) || '1.0.0';
  const directSet = new Set(Object.keys((rawPkg?.dependencies as Record<string, string>) ?? {}));

  const seen = new Map<string, ParsedDependency>();
  if (files['package-lock.json']) {
    const lock = JSON.parse(files['package-lock.json']) as {
      packages?: Record<string, { version?: string; dev?: boolean; optional?: boolean }>;
    };
    for (const [pkgPath, entry] of Object.entries(lock.packages ?? {})) {
      const marker = 'node_modules/';
      const idx = pkgPath.lastIndexOf(marker);
      if (idx === -1 || !entry.version) continue;
      const name = pkgPath.slice(idx + marker.length);
      seen.set(`${name}@${entry.version}`, {
        ecosystem: 'npm',
        name,
        version: entry.version,
        purl: buildNpmPurl(name, entry.version),
        scope: entry.dev ? 'dev' : entry.optional ? 'optional' : 'required',
        direct: !pkgPath.slice(0, idx).includes(marker) || directSet.has(name),
        sourceFile: 'package-lock.json',
      });
    }
  } else if (rawPkg?.dependencies) {
    for (const [name, verRaw] of Object.entries(rawPkg.dependencies as Record<string, string>)) {
      const version = String(verRaw).replace(/^[~^=<>v\s]+/, '');
      seen.set(`${name}@${version}`, {
        ecosystem: 'npm',
        name,
        version,
        purl: buildNpmPurl(name, version),
        scope: 'required',
        direct: true,
        sourceFile: 'package.json',
      });
    }
  }

  return {
    projectName,
    projectVersion,
    dependencies: Array.from(seen.values()),
    rawPackageJson: rawPkg,
  };
}

/** Deterministic browser JS/TS AST-style analyzer matching AnalyzedProjectGraph. */
function analyzeVirtualFilesReachability(files: Record<string, string>): AnalyzedProjectGraph {
  const nodesMap = new Map<string, CallGraphNode>();
  const edges: CallGraphEdge[] = [];
  const adj = new Map<string, string[]>();
  const hazards: DynamicHazard[] = [];
  const packagesImported: Record<string, CallSite[]> = {};
  const allCallSitesByPkg = new Map<string, CallSite[]>();

  const sourceEntries = Object.entries(files).filter(([p]) => /\.(ts|tsx|js|jsx|mjs)$/.test(p));
  const pkgJson = files['package.json'] ? JSON.parse(files['package.json']) : null;
  const mainEntry = typeof pkgJson?.main === 'string' ? pkgJson.main.replace(/^\.\//, '') : '';

  const definedNames = new Map<string, string[]>();
  const pendingCalls: Array<{ callerId: string; targetName: string }> = [];

  for (const [relPath, text] of sourceEntries) {
    const lines = text.split(/\r?\n/);
    const isEntryFile =
      relPath === mainEntry || /(^|\/)(index|main|server|app|cli|handler|route)\.(ts|tsx|js|jsx|mjs)$/.test(relPath);
    const modId = `${relPath}::<module>`;
    nodesMap.set(modId, {
      id: modId,
      label: modId,
      kind: isEntryFile ? 'entrypoint' : 'function',
      file: relPath,
      line: 1,
    });

    const extAliases = new Map<string, { pkg: string; exp: string }>();
    let currentFnId = modId;
    let braceDepth = 0;
    let fnStartDepth = 0;

    lines.forEach((line, idx) => {
      const ln = idx + 1;
      const trimmed = line.trim();

      // ES imports
      const impDefault = trimmed.match(/^import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/);
      if (impDefault && !impDefault[2].startsWith('.')) {
        const [, alias, spec] = impDefault;
        const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
        extAliases.set(alias, { pkg, exp: spec.includes('/') && !spec.startsWith('@') ? spec.split('/')[1] : 'default' });
      }
      const impNamed = trimmed.match(/^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/);
      if (impNamed && !impNamed[2].startsWith('.')) {
        const [, inner, spec] = impNamed;
        const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
        for (const part of inner.split(',')) {
          const [orig, alias] = part.trim().split(/\s+as\s+/);
          if (orig) extAliases.set((alias || orig).trim(), { pkg, exp: orig.trim() });
        }
      }
      const impStar = trimmed.match(/^import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/);
      if (impStar && !impStar[2].startsWith('.')) {
        const [, alias, spec] = impStar;
        const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
        extAliases.set(alias, { pkg, exp: '*' });
      }

      // Dynamic hazards
      if (/\beval\s*\(/.test(trimmed)) {
        hazards.push({ file: relPath, line: ln, column: 1, kind: 'eval', snippet: trimmed });
      }
      if (/new\s+Function\s*\(/.test(trimmed)) {
        hazards.push({ file: relPath, line: ln, column: 1, kind: 'new-function', snippet: trimmed });
      }
      const dynReq = trimmed.match(/\brequire\s*\(\s*([^)'"]+)\s*\)/);
      if (dynReq) {
        hazards.push({ file: relPath, line: ln, column: 1, kind: 'dynamic-require', snippet: trimmed });
      }

      // Function declarations
      const fnMatch = trimmed.match(/^(export\s+)?(async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (fnMatch) {
        const isExported = Boolean(fnMatch[1]);
        const fnName = fnMatch[3];
        const fnId = `${relPath}::${fnName}`;
        nodesMap.set(fnId, {
          id: fnId,
          label: fnName,
          kind: isExported ? 'entrypoint' : 'function',
          file: relPath,
          line: ln,
        });
        definedNames.set(fnName, [...(definedNames.get(fnName) ?? []), fnId]);
        currentFnId = fnId;
        fnStartDepth = braceDepth;
      }

      // Track braces to reset function scope cleanly (never exit on the declaration line itself)
      for (const ch of trimmed) {
        if (ch === '{') braceDepth++;
        else if (ch === '}') {
          braceDepth = Math.max(0, braceDepth - 1);
          if (!fnMatch && braceDepth <= fnStartDepth && currentFnId !== modId) {
            currentFnId = modId;
          }
        }
      }

      // External member calls `alias.member(` or direct `importedFn(`
      for (const [alias, info] of extAliases) {
        const memberRe = new RegExp(`\\b${alias}\\.([A-Za-z_$][\\w$]*)\\s*\\(`, 'g');
        let mm: RegExpExecArray | null;
        while ((mm = memberRe.exec(trimmed)) !== null) {
          const site: CallSite = {
            file: relPath,
            line: ln,
            column: mm.index + 1,
            callerFunction: currentFnId,
            importedAs: alias,
            memberCalled: mm[1],
            snippet: trimmed.slice(0, 140),
          };
          if (!packagesImported[info.pkg]) packagesImported[info.pkg] = [];
          packagesImported[info.pkg].push(site);
          allCallSitesByPkg.set(info.pkg, [...(allCallSitesByPkg.get(info.pkg) ?? []), site]);

          const extNodeId = `ext:${info.pkg}.${mm[1]}`;
          if (!nodesMap.has(extNodeId)) {
            nodesMap.set(extNodeId, {
              id: extNodeId,
              label: `${info.pkg}.${mm[1]}`,
              kind: 'external-symbol',
              file: relPath,
              line: ln,
            });
          }
          edges.push({ from: currentFnId, to: extNodeId, kind: 'imports' });
        }

        const directRe = new RegExp(`(?<!\\.)\\b${alias}\\s*\\(`, 'g');
        let dm: RegExpExecArray | null;
        while ((dm = directRe.exec(trimmed)) !== null) {
          if (trimmed.startsWith('import ')) continue;
          const site: CallSite = {
            file: relPath,
            line: ln,
            column: dm.index + 1,
            callerFunction: currentFnId,
            importedAs: alias,
            memberCalled: info.exp === '*' ? alias : info.exp,
            snippet: trimmed.slice(0, 140),
          };
          if (!packagesImported[info.pkg]) packagesImported[info.pkg] = [];
          packagesImported[info.pkg].push(site);
          allCallSitesByPkg.set(info.pkg, [...(allCallSitesByPkg.get(info.pkg) ?? []), site]);

          const extNodeId = `ext:${info.pkg}.${site.memberCalled}`;
          if (!nodesMap.has(extNodeId)) {
            nodesMap.set(extNodeId, {
              id: extNodeId,
              label: `${info.pkg}.${site.memberCalled}`,
              kind: 'external-symbol',
              file: relPath,
              line: ln,
            });
          }
          edges.push({ from: currentFnId, to: extNodeId, kind: 'imports' });
        }
      }

      // Local function invocations `someFn(`
      if (!fnMatch) {
        const callRe = /\b([A-Za-z_$][\w$]*)\s*\(/g;
        let cm: RegExpExecArray | null;
        while ((cm = callRe.exec(trimmed)) !== null) {
          const callee = cm[1];
          if (!extAliases.has(callee)) {
            pendingCalls.push({ callerId: currentFnId, targetName: callee });
          }
        }
      }
    });
  }

  for (const call of pendingCalls) {
    const targets = definedNames.get(call.targetName) ?? [];
    for (const tid of targets) {
      if (tid === call.callerId) continue;
      adj.set(call.callerId, [...(adj.get(call.callerId) ?? []), tid]);
      edges.push({ from: call.callerId, to: tid, kind: 'calls' });
    }
  }

  const reachableFunctionIds = new Set<string>();
  const parentPath = new Map<string, string[]>();
  const queue: string[] = [];
  for (const node of nodesMap.values()) {
    if (node.kind === 'entrypoint') {
      reachableFunctionIds.add(node.id);
      parentPath.set(node.id, [node.id]);
      queue.push(node.id);
    }
  }
  while (queue.length > 0) {
    const curr = queue.shift()!;
    for (const nxt of adj.get(curr) ?? []) {
      if (!reachableFunctionIds.has(nxt)) {
        reachableFunctionIds.add(nxt);
        parentPath.set(nxt, [...(parentPath.get(curr) ?? [curr]), nxt]);
        queue.push(nxt);
      }
    }
  }

  const reachableChainsByPkg = new Map<string, Map<string, string[]>>();
  for (const [pkg, sites] of allCallSitesByPkg) {
    const symbolMap = new Map<string, string[]>();
    for (const site of sites) {
      if (!reachableFunctionIds.has(site.callerFunction)) continue;
      const sym = site.memberCalled ?? '*';
      if (!symbolMap.has(sym)) {
        const prefix = parentPath.get(site.callerFunction) ?? [site.callerFunction];
        symbolMap.set(sym, [...prefix, `${pkg}.${sym} (${site.file}:${site.line})`]);
      }
    }
    if (symbolMap.size > 0) reachableChainsByPkg.set(pkg, symbolMap);
  }

  return {
    summary: {
      filesScanned: sourceEntries.length,
      entrypointsFound: Array.from(nodesMap.values()).filter((n) => n.kind === 'entrypoint').length,
      functionsMapped: Array.from(nodesMap.values()).filter((n) => n.kind !== 'external-symbol').length,
      edgesMapped: edges.length,
      dynamicHazards: hazards,
      packagesImported,
      nodes: Array.from(nodesMap.values()),
      edges,
    },
    reachableChainsByPkg,
    allCallSitesByPkg,
    reachableFunctionIds,
  };
}

interface SnapshotVulnSpec {
  id: string;
  cve: string;
  pkg: string;
  version: string;
  fix: string[];
  sev: VulnerabilityIntel['severityLabel'];
  epss: number;
  summary: string;
}

const VERIFIED_OSV_FALLBACK: SnapshotVulnSpec[] = [
  { id: 'GHSA-ghr5-ch3p-vcr6', cve: 'CVE-2024-33883', pkg: 'ejs', version: '3.1.9', fix: ['3.1.10'], sev: 'MEDIUM', epss: 0.006, summary: 'ejs lacks certain pollution protection' },
  { id: 'GHSA-8cf7-32gw-wr33', cve: 'CVE-2022-23539', pkg: 'jsonwebtoken', version: '8.5.1', fix: ['9.0.0'], sev: 'HIGH', epss: 0.005, summary: 'jsonwebtoken unrestricted key type could lead to legacy keys usage' },
  { id: 'GHSA-hjrf-2m68-5959', cve: 'CVE-2022-23541', pkg: 'jsonwebtoken', version: '8.5.1', fix: ['9.0.0'], sev: 'MEDIUM', epss: 0.008, summary: 'jsonwebtoken insecure implementation of key retrieval function could lead to Forgeable Tokens' },
  { id: 'GHSA-qwph-4952-7xr6', cve: 'CVE-2022-23540', pkg: 'jsonwebtoken', version: '8.5.1', fix: ['9.0.0'], sev: 'MEDIUM', epss: 0.006, summary: 'jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()' },
  { id: 'GHSA-35jh-r3h4-6jhm', cve: 'CVE-2021-23337', pkg: 'lodash', version: '4.17.20', fix: ['4.17.21'], sev: 'HIGH', epss: 0.202, summary: 'Command Injection in lodash' },
  { id: 'GHSA-r5fr-rjxr-66jc', cve: 'CVE-2026-4800', pkg: 'lodash', version: '4.17.20', fix: ['4.18.0'], sev: 'HIGH', epss: 0.029, summary: 'lodash vulnerable to Code Injection via _.template imports key names' },
  { id: 'GHSA-29mw-wpgm-hmr9', cve: 'CVE-2020-28500', pkg: 'lodash', version: '4.17.20', fix: ['4.17.21'], sev: 'MEDIUM', epss: 0.074, summary: 'Regular Expression Denial of Service (ReDoS) in lodash' },
  { id: 'GHSA-xxjr-mmjv-4gpg', cve: 'CVE-2025-13465', pkg: 'lodash', version: '4.17.20', fix: ['4.17.23', '4.18.0'], sev: 'MEDIUM', epss: 0.018, summary: 'Lodash has Prototype Pollution Vulnerability in _.unset, _.omit, and _.pullAt functions' },
  { id: 'GHSA-23c5-xmqv-rm74', cve: 'CVE-2026-27904', pkg: 'minimatch', version: '3.0.4', fix: ['3.1.4'], sev: 'HIGH', epss: 0.005, summary: 'minimatch ReDoS: nested *() extglobs generate catastrophically backtracking regular expressions' },
  { id: 'GHSA-3ppc-4f35-3m26', cve: 'CVE-2026-26996', pkg: 'minimatch', version: '3.0.4', fix: ['3.1.3'], sev: 'HIGH', epss: 0.006, summary: 'minimatch has a ReDoS via repeated wildcards with non-matching literal in pattern' },
  { id: 'GHSA-7r86-cg39-jmmj', cve: 'CVE-2026-27903', pkg: 'minimatch', version: '3.0.4', fix: ['3.1.3'], sev: 'HIGH', epss: 0.006, summary: 'minimatch has ReDoS: matchOne() combinatorial backtracking' },
  { id: 'GHSA-f8q6-p94x-37v3', cve: 'CVE-2022-3517', pkg: 'minimatch', version: '3.0.4', fix: ['3.0.5'], sev: 'HIGH', epss: 0.023, summary: 'minimatch ReDoS vulnerability' },
  { id: 'GHSA-5c6j-r48x-rmvq', cve: 'GHSA-5c6j-r48x-rmvq', pkg: 'serialize-javascript', version: '3.1.0', fix: ['7.0.3'], sev: 'HIGH', epss: null as unknown as number, summary: 'Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()' },
  { id: 'GHSA-m5mm-p8h7-m29v', cve: 'CVE-2026-115754', pkg: 'serialize-javascript', version: '3.1.0', fix: ['7.1.3'], sev: 'LOW', epss: 0.002, summary: 'Serialize JavaScript: Cross-site scripting (XSS) via unescaped </script' },
];

async function queryOsvBrowserIntel(deps: ParsedDependency[], offlineOnly: boolean): Promise<VulnerabilityIntel[]> {
  if (!offlineOnly) {
    try {
      const batchRes = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
        }),
      });
      if (batchRes.ok) {
        const batchJson = (await batchRes.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
        const pairs: Array<{ dep: ParsedDependency; id: string }> = [];
        const uniqueIds = new Set<string>();
        deps.forEach((dep, idx) => {
          for (const v of batchJson.results?.[idx]?.vulns ?? []) {
            pairs.push({ dep, id: v.id });
            uniqueIds.add(v.id);
          }
        });
        const details = await Promise.all(
          Array.from(uniqueIds).map(async (id) => {
            const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
            return [id, r.ok ? ((await r.json()) as Record<string, unknown>) : null] as const;
          })
        );
        const detailMap = new Map(details);
        const seen = new Set<string>();
        const intel: VulnerabilityIntel[] = [];
        for (const { dep, id } of pairs) {
          const d = detailMap.get(id) as
            | {
                id: string;
                aliases?: string[];
                summary?: string;
                details?: string;
                database_specific?: { severity?: string; cvss_score?: number };
                affected?: Array<{ package?: { name?: string }; ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
              }
            | undefined;
          if (!d) continue;
          const cveId = d.id.startsWith('CVE-') ? d.id : (d.aliases ?? []).find((a) => a.startsWith('CVE-')) ?? null;
          const dedupe = `${dep.name}@${dep.version}:${cveId ?? d.id}`;
          if (seen.has(dedupe)) continue;
          seen.add(dedupe);
          const rawSev = (d.database_specific?.severity ?? 'UNKNOWN').toUpperCase();
          const severityLabel: VulnerabilityIntel['severityLabel'] =
            rawSev === 'MODERATE'
              ? 'MEDIUM'
              : rawSev === 'CRITICAL' || rawSev === 'HIGH' || rawSev === 'MEDIUM' || rawSev === 'LOW'
                ? rawSev
                : 'UNKNOWN';
          const fixedVersions = Array.from(
            new Set(
              (d.affected ?? [])
                .filter((a) => !a.package?.name || a.package.name.toLowerCase() === dep.name.toLowerCase())
                .flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter((x): x is string => Boolean(x))))
            )
          );
          intel.push({
            id: d.id,
            aliases: d.aliases ?? [],
            cveId,
            packageName: dep.name,
            ecosystem: dep.ecosystem,
            installedVersion: dep.version,
            purl: dep.purl,
            summary: d.summary ?? d.details?.slice(0, 160) ?? id,
            details: d.details ?? '',
            severityLabel,
            cvssScore: d.database_specific?.cvss_score ?? null,
            fixedVersions,
            inCisaKev: false,
            kevDueDate: null,
            epssScore: null,
            epssPercentile: null,
            intelSource: 'live',
            references: [],
          });
        }
        return intel;
      }
    } catch {
      // Fall through cleanly to verified snapshot
    }
  }

  const out: VulnerabilityIntel[] = [];
  for (const dep of deps) {
    for (const s of VERIFIED_OSV_FALLBACK) {
      if (s.pkg === dep.name && s.version === dep.version) {
        out.push({
          id: s.id,
          aliases: s.cve.startsWith('CVE-') ? [s.cve] : [],
          cveId: s.cve.startsWith('CVE-') ? s.cve : null,
          packageName: dep.name,
          ecosystem: 'npm',
          installedVersion: dep.version,
          purl: dep.purl,
          summary: s.summary,
          details: s.summary,
          severityLabel: s.sev,
          cvssScore: null,
          fixedVersions: s.fix,
          inCisaKev: false,
          kevDueDate: null,
          epssScore: s.epss ?? null,
          epssPercentile: null,
          intelSource: 'cache',
          references: [],
        });
      }
    }
  }
  return out;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((x) => canonicalJson(x)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(',')}}`;
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toSpkiPem(spkiBytes: Uint8Array): string {
  const b64 = toBase64(spkiBytes);
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

function fromSpkiPem(pem: string): Uint8Array {
  const clean = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return fromBase64(clean);
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function signOpenVexInBrowser(document: OpenVexDocument): Promise<SignedVexBundle> {
  const canonical = canonicalJson(document);
  const canonicalDigestSha256 = await sha256Hex(canonical);
  const keyPair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const sigBuf = await crypto.subtle.sign(
    { name: 'Ed25519' },
    keyPair.privateKey,
    new TextEncoder().encode(canonical)
  );
  const spkiBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  return {
    algorithm: 'Ed25519',
    canonicalDigestSha256,
    signatureBase64: toBase64(new Uint8Array(sigBuf)),
    publicKeyPem: toSpkiPem(new Uint8Array(spkiBuf)),
    signedAt: new Date().toISOString(),
    document,
  };
}

export async function verifyVexBundleInBrowser(bundle: SignedVexBundle): Promise<{
  valid: boolean;
  recomputedSha256: string;
  claimedSha256: string;
  statementCount: number;
  reason: string;
}> {
  try {
    const canonical = canonicalJson(bundle.document);
    const recomputedSha256 = await sha256Hex(canonical);
    if (recomputedSha256 !== bundle.canonicalDigestSha256) {
      return {
        valid: false,
        recomputedSha256,
        claimedSha256: bundle.canonicalDigestSha256,
        statementCount: bundle.document?.statements?.length ?? 0,
        reason: 'SHA-256 digest mismatch: OpenVEX payload was altered after signing.',
      };
    }
    const pubKey = await crypto.subtle.importKey(
      'spki',
      fromSpkiPem(bundle.publicKeyPem).buffer as ArrayBuffer,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' },
      pubKey,
      fromBase64(bundle.signatureBase64).buffer as ArrayBuffer,
      new TextEncoder().encode(canonical)
    );
    return {
      valid: ok,
      recomputedSha256,
      claimedSha256: bundle.canonicalDigestSha256,
      statementCount: bundle.document?.statements?.length ?? 0,
      reason: ok
        ? 'Ed25519 cryptographic signature and canonical SHA-256 digest verified (WebCrypto).'
        : 'Ed25519 signature verification failed against public key.',
    };
  } catch (err) {
    return {
      valid: false,
      recomputedSha256: '',
      claimedSha256: bundle?.canonicalDigestSha256 ?? '',
      statementCount: 0,
      reason: err instanceof Error ? err.message : 'Invalid SignedVexBundle',
    };
  }
}

export async function runVirtualRepoScan(
  targetPath: string,
  customFiles?: Record<string, string>,
  offlineOnly = false
): Promise<{ report: ScanReport; files: Record<string, string> }> {
  const startedAt = Date.now();
  const repo = BUILTIN_SAMPLE_REPOS[targetPath] ?? BUILTIN_SAMPLE_REPOS['examples/acme-eu-gateway'];
  const files = customFiles ?? repo.files;
  const manifest = parseVirtualLockfile(files);

  const sbom: CycloneDxSbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'VEXProof', name: 'vexproof-browser-compiler', version: '1.0.0' }],
      component: {
        type: 'application',
        'bom-ref': `pkg:application/${encodeURIComponent(manifest.projectName)}@${manifest.projectVersion}`,
        name: manifest.projectName,
        version: manifest.projectVersion,
      },
    },
    components: manifest.dependencies.map((d) => ({
      type: 'library',
      'bom-ref': d.purl,
      name: d.name,
      version: d.version,
      purl: d.purl,
      scope: d.scope === 'dev' ? 'optional' : 'required',
    })),
  };

  const vulns = await queryOsvBrowserIntel(manifest.dependencies, offlineOnly);
  const graph = analyzeVirtualFilesReachability(files);
  const directSet = new Set(manifest.dependencies.filter((d) => d.direct).map((d) => d.name.toLowerCase()));
  const findings = correlateReachabilityFindings(vulns, graph, directSet);

  const now = new Date().toISOString();
  const openVexDoc: OpenVexDocument = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${crypto.randomUUID()}`,
    author: 'VEXProof Automated Reachability Compiler',
    role: 'EU CRA Security Evidence Generator',
    timestamp: now,
    version: 1,
    tooling: 'VEXProof/1.0.0 (Browser WebCrypto + OSV.dev + AST Call-Graph)',
    statements: findings.map((f) => ({
      vulnerability: {
        '@id': `https://osv.dev/vulnerability/${encodeURIComponent(f.vuln.id)}`,
        name: f.vuln.cveId ?? f.vuln.id,
        description: f.vuln.summary,
        aliases: Array.from(new Set([f.vuln.id, ...f.vuln.aliases])),
      },
      products: [
        {
          '@id': `pkg:application/${encodeURIComponent(manifest.projectName)}@${manifest.projectVersion}`,
          subcomponents: [{ '@id': f.vuln.purl }],
        },
      ],
      status: f.status,
      ...(f.status === 'not_affected' ? { justification: f.justification ?? 'vulnerable_code_not_in_execute_path' } : {}),
      status_notes: f.rationale,
      timestamp: now,
    })),
  };

  const signedVex = await signOpenVexInBrowser(openVexDoc);
  const patchPlan = buildPatchPlan(findings, manifest.rawPackageJson);

  const affectedCount = findings.filter((f) => f.status === 'affected').length;
  const notAffectedCount = findings.filter((f) => f.status === 'not_affected').length;
  const underInvestigationCount = findings.filter((f) => f.status === 'under_investigation').length;
  const totalVulnerabilities = findings.length;

  const report: ScanReport = {
    projectName: manifest.projectName,
    projectVersion: manifest.projectVersion,
    targetPath,
    scannedAt: now,
    metrics: {
      totalDependencies: manifest.dependencies.length,
      directDependencies: manifest.dependencies.filter((d) => d.direct).length,
      totalVulnerabilities,
      affectedCount,
      notAffectedCount,
      underInvestigationCount,
      noiseReductionPercent: totalVulnerabilities > 0 ? Math.round((notAffectedCount / totalVulnerabilities) * 100) : 100,
      durationMs: Date.now() - startedAt,
      intelMode: vulns.some((v) => v.intelSource === 'live') ? 'live' : 'cache',
    },
    dependencies: manifest.dependencies,
    sbom,
    astSummary: graph.summary,
    findings,
    signedVex,
    cyclonedxVex: { ...sbom, vulnerabilitiesCount: findings.length },
    patchPlan,
  };

  return { report, files };
}

export function extractVirtualSnippet(
  files: Record<string, string>,
  file: string,
  focusLine: number
) {
  const raw = files[file];
  if (!raw) return null;
  const lines = raw.split(/\r?\n/);
  const start = Math.max(1, focusLine - 6);
  const end = Math.min(lines.length, focusLine + 6);
  return {
    file,
    focusLine,
    snippet: lines.slice(start - 1, end).map((content, idx) => ({
      lineNumber: start + idx,
      content,
      isFocus: start + idx === focusLine,
    })),
  };
}
