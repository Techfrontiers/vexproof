import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { correlateReachabilityFindings } from '../src/core/correlator.js';
import { buildPatchPlan } from '../src/core/patch-planner.js';
import { analyzeProjectReachability } from '../src/core/reachability-ast.js';
import { generateCycloneDxSbom, parseProjectManifests } from '../src/core/sbom-parser.js';
import { scanProject } from '../src/core/scanner.js';
import type { VulnerabilityIntel } from '../src/core/types.js';
import { createVexproofApp } from '../src/server/index.js';
import {
  compileOpenVexDocument,
  signOpenVexDocument,
  verifyVexBundle,
} from '../src/core/vex-compiler.js';

const ROOT = process.cwd();
const ACME_DIR = path.join(ROOT, 'examples', 'acme-eu-gateway');
const FINTECH_DIR = path.join(ROOT, 'examples', 'fintech-worker');
const DYNAMIC_DIR = path.join(ROOT, 'examples', 'legacy-dynamic-plugin');

function sampleIntel(
  id: string,
  cveId: string,
  pkg: string,
  ver: string,
  summary: string,
  fixedVersions: string[]
): VulnerabilityIntel {
  return {
    id,
    aliases: [cveId],
    cveId,
    packageName: pkg,
    ecosystem: 'npm',
    installedVersion: ver,
    purl: `pkg:npm/${pkg}@${ver}`,
    summary,
    details: summary,
    severityLabel: 'HIGH',
    cvssScore: 7.5,
    fixedVersions,
    inCisaKev: false,
    kevDueDate: null,
    epssScore: 0.42,
    epssPercentile: 0.91,
    intelSource: 'live',
    references: [],
  };
}

describe('VEXProof Core Engine', () => {
  it('parses package-lock.json and generates CycloneDX 1.5 SBOM', () => {
    const manifest = parseProjectManifests(ACME_DIR);
    expect(manifest.projectName).toBe('acme-eu-gateway');
    expect(manifest.dependencies.length).toBe(5);

    const sbom = generateCycloneDxSbom(
      manifest.projectName,
      manifest.projectVersion,
      manifest.dependencies
    );
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components.some((c) => c.purl === 'pkg:npm/lodash@4.17.20')).toBe(true);
  });

  it('proves reachable vs dead-code vs unimported CVEs via TypeScript AST call-graph', () => {
    const graph = analyzeProjectReachability(ACME_DIR);
    expect(graph.summary.filesScanned).toBe(3);
    expect(graph.summary.dynamicHazards.length).toBe(0);

    const directDeps = new Set(['ejs', 'jsonwebtoken', 'lodash', 'minimatch', 'serialize-javascript']);
    const vulns: VulnerabilityIntel[] = [
      sampleIntel(
        'GHSA-35jh-r3h4-6jhm',
        'CVE-2021-23337',
        'lodash',
        '4.17.20',
        'Command injection in lodash template()',
        ['4.17.21']
      ),
      sampleIntel(
        'GHSA-ghr5-ch3p-vcr6',
        'CVE-2024-33883',
        'ejs',
        '3.1.9',
        'Template pollution/XSS via ejs render',
        ['3.1.10']
      ),
      sampleIntel(
        'GHSA-27h2-hvpr-p74q',
        'CVE-2022-23529',
        'jsonwebtoken',
        '8.5.1',
        'Insecure key retrieval in jsonwebtoken verify',
        ['9.0.0']
      ),
      sampleIntel(
        'GHSA-7rfc-gv3f-8f4j',
        'CVE-2020-7660',
        'serialize-javascript',
        '3.1.0',
        'Cross-site scripting in serialize-javascript',
        ['3.1.1']
      ),
      sampleIntel(
        'GHSA-f8q6-p94x-37v3',
        'CVE-2022-3517',
        'minimatch',
        '3.0.4',
        'ReDoS in minimatch glob matching',
        ['3.0.5']
      ),
    ];

    const findings = correlateReachabilityFindings(vulns, graph, directDeps);
    const byPkg = Object.fromEntries(findings.map((f) => [f.vuln.packageName, f]));

    expect(byPkg.lodash.status).toBe('affected');
    expect(byPkg.lodash.matchedSymbols).toContain('template');
    expect(byPkg.lodash.callPath.length).toBeGreaterThanOrEqual(2);

    expect(byPkg.ejs.status).toBe('affected');
    expect(byPkg.jsonwebtoken.status).toBe('affected');

    // serialize-javascript is called ONLY in unexported dead helper legacyDeadDebugSerializer()
    expect(byPkg['serialize-javascript'].status).toBe('not_affected');
    expect(byPkg['serialize-javascript'].justification).toBe('vulnerable_code_not_in_execute_path');

    // minimatch is never imported in runtime source files
    expect(byPkg.minimatch.status).toBe('not_affected');

    const patchPlan = buildPatchPlan(findings, null);
    const patchedPkgs = patchPlan.actions.map((a) => a.packageName);
    expect(patchedPkgs).toContain('lodash');
    expect(patchedPkgs).toContain('ejs');
    expect(patchedPkgs).not.toContain('minimatch');
    expect(patchedPkgs).not.toContain('serialize-javascript');
  });

  it('suppresses lodash.template CVE when only safe lodash.chunk is invoked', () => {
    const graph = analyzeProjectReachability(FINTECH_DIR);
    expect(graph.summary.dynamicHazards.length).toBe(0);

    const vulns = [
      sampleIntel(
        'GHSA-35jh-r3h4-6jhm',
        'CVE-2021-23337',
        'lodash',
        '4.17.20',
        'Command injection in lodash template()',
        ['4.17.21']
      ),
    ];
    const findings = correlateReachabilityFindings(vulns, graph, new Set(['lodash']));
    expect(findings[0].status).toBe('not_affected');
    expect(findings[0].justification).toBe('vulnerable_code_not_in_execute_path');
  });

  it('enforces honest under_investigation status when dynamic require() is present', () => {
    const graph = analyzeProjectReachability(DYNAMIC_DIR);
    expect(graph.summary.dynamicHazards.length).toBe(1);
    expect(graph.summary.dynamicHazards[0].kind).toBe('dynamic-require');

    const vulns = [
      sampleIntel(
        'GHSA-f8q6-p94x-37v3',
        'CVE-2022-3517',
        'minimatch',
        '3.0.4',
        'ReDoS in minimatch',
        ['3.0.5']
      ),
    ];
    const findings = correlateReachabilityFindings(vulns, graph, new Set(['minimatch']));
    expect(findings[0].status).toBe('under_investigation');
    expect(findings[0].craPriority).toBe('VERIFY_DYNAMIC');
  });

  it('signs OpenVEX v0.2.0 with Ed25519 and rejects 1-byte tampering', () => {
    const doc = compileOpenVexDocument('acme-eu-gateway', '2.4.1', []);
    const signed = signOpenVexDocument(doc);
    const validResult = verifyVexBundle(signed);
    expect(validResult.valid).toBe(true);

    const tampered = structuredClone(signed);
    tampered.document.author = 'Tampered Attacker';
    const invalidResult = verifyVexBundle(tampered);
    expect(invalidResult.valid).toBe(false);
    expect(invalidResult.reason).toContain('SHA-256 digest mismatch');
  });

  it('executes end-to-end live scan against OSV.dev for acme-eu-gateway', async () => {
    const report = await scanProject(ACME_DIR, { cacheBaseDir: ROOT });
    expect(report.metrics.totalDependencies).toBe(5);
    expect(report.metrics.totalVulnerabilities).toBeGreaterThanOrEqual(4);
    expect(report.metrics.affectedCount).toBeGreaterThanOrEqual(2);
    expect(report.metrics.notAffectedCount).toBeGreaterThanOrEqual(1);
    expect(verifyVexBundle(report.signedVex).valid).toBe(true);
  }, 25000);

  it('serves samples, scan results, and tamper verification over HTTP API', async () => {
    const app = createVexproofApp();
    const server = await new Promise<import('node:http').Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    try {
      const addr = server.address();
      if (!addr || typeof addr === 'string') throw new Error('Invalid server address');
      const base = `http://127.0.0.1:${addr.port}`;

      const samplesRes = await fetch(`${base}/api/samples`);
      expect(samplesRes.status).toBe(200);
      const samplesJson = (await samplesRes.json()) as { samples: Array<{ id: string }> };
      expect(samplesJson.samples.some((s) => s.id === 'acme-eu-gateway')).toBe(true);

      const scanRes = await fetch(`${base}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetPathOrUrl: 'examples/fintech-worker' }),
      });
      expect(scanRes.status).toBe(200);
      const scanJson = (await scanRes.json()) as {
        metrics: { affectedCount: number; notAffectedCount: number };
        signedVex: unknown;
      };
      expect(scanJson.metrics.affectedCount).toBe(0);
      expect(scanJson.metrics.notAffectedCount).toBeGreaterThanOrEqual(1);

      const verifyRes = await fetch(`${base}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bundle: scanJson.signedVex }),
      });
      expect(verifyRes.status).toBe(200);
      const verifyJson = (await verifyRes.json()) as { valid: boolean };
      expect(verifyJson.valid).toBe(true);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 25000);
});
