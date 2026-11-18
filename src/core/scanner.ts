import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { correlateReachabilityFindings } from './correlator.js';
import { buildPatchPlan } from './patch-planner.js';
import { analyzeProjectReachability } from './reachability-ast.js';
import { generateCycloneDxSbom, parseProjectManifests } from './sbom-parser.js';
import { correlateThreatIntel } from './threat-intel.js';
import type { ScanReport } from './types.js';
import { compileCycloneDxVex, compileOpenVexDocument, signOpenVexDocument } from './vex-compiler.js';

export interface ScanOptions {
  offlineOnly?: boolean;
  cacheBaseDir?: string;
}

function isRemoteGitUrl(input: string): boolean {
  return /^https:\/\/(github\.com|gitlab\.com)\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(\.git)?\/?$/.test(
    input.trim()
  );
}

export async function scanProject(targetInput: string, options?: ScanOptions): Promise<ScanReport> {
  const startedAt = Date.now();
  let cleanupTempDir: string | null = null;
  let resolvedTarget = targetInput.trim();

  if (isRemoteGitUrl(resolvedTarget)) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vexproof-repo-'));
    cleanupTempDir = tmpDir;
    execFileSync('git', ['clone', '--depth', '1', resolvedTarget, tmpDir], {
      stdio: 'pipe',
      timeout: 45000,
    });
    resolvedTarget = tmpDir;
  } else {
    resolvedTarget = path.resolve(resolvedTarget);
  }

  if (!fs.existsSync(resolvedTarget)) {
    throw new Error(`Target repository path does not exist: ${resolvedTarget}`);
  }

  try {
    const manifest = parseProjectManifests(resolvedTarget);
    const sbom = generateCycloneDxSbom(
      manifest.projectName,
      manifest.projectVersion,
      manifest.dependencies
    );

    const [vulns, graph] = await Promise.all([
      correlateThreatIntel(manifest.dependencies, {
        cacheBaseDir: options?.cacheBaseDir ?? process.cwd(),
        offlineOnly: options?.offlineOnly,
      }),
      Promise.resolve(analyzeProjectReachability(resolvedTarget)),
    ]);

    const directDepSet = new Set(
      manifest.dependencies.filter((d) => d.direct).map((d) => d.name.toLowerCase())
    );
    const findings = correlateReachabilityFindings(vulns, graph, directDepSet);

    const openVexDoc = compileOpenVexDocument(
      manifest.projectName,
      manifest.projectVersion,
      findings
    );
    const signedVex = signOpenVexDocument(openVexDoc);
    const cyclonedxVex = compileCycloneDxVex(sbom, findings);
    const patchPlan = buildPatchPlan(findings, manifest.rawPackageJson);

    const affectedCount = findings.filter((f) => f.status === 'affected').length;
    const notAffectedCount = findings.filter((f) => f.status === 'not_affected').length;
    const underInvestigationCount = findings.filter((f) => f.status === 'under_investigation').length;
    const totalVulns = findings.length;
    const noiseReductionPercent =
      totalVulns > 0 ? Math.round((notAffectedCount / totalVulns) * 100) : 100;

    const intelSources = new Set(vulns.map((v) => v.intelSource));
    const intelMode =
      intelSources.size === 0
        ? 'live'
        : intelSources.size === 1
          ? (Array.from(intelSources)[0] as 'live' | 'cache')
          : 'mixed';

    return {
      projectName: manifest.projectName,
      projectVersion: manifest.projectVersion,
      targetPath: targetInput,
      scannedAt: new Date().toISOString(),
      metrics: {
        totalDependencies: manifest.dependencies.length,
        directDependencies: manifest.dependencies.filter((d) => d.direct).length,
        totalVulnerabilities: totalVulns,
        affectedCount,
        notAffectedCount,
        underInvestigationCount,
        noiseReductionPercent,
        durationMs: Date.now() - startedAt,
        intelMode,
      },
      dependencies: manifest.dependencies,
      sbom,
      astSummary: graph.summary,
      findings,
      signedVex,
      cyclonedxVex,
      patchPlan,
    };
  } finally {
    if (cleanupTempDir) {
      fs.rmSync(cleanupTempDir, { recursive: true, force: true });
    }
  }
}
