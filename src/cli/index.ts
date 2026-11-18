#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from '../core/scanner.js';
import type { SignedVexBundle } from '../core/types.js';
import { verifyVexBundle } from '../core/vex-compiler.js';

function writeReportArtifacts(outDir: string, report: Awaited<ReturnType<typeof scanProject>>) {
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'bom.json'), JSON.stringify(report.sbom, null, 2), 'utf8');
  fs.writeFileSync(
    path.join(outDir, 'bom-vex.json'),
    JSON.stringify(report.cyclonedxVex, null, 2),
    'utf8'
  );
  fs.writeFileSync(
    path.join(outDir, 'vex.json'),
    JSON.stringify(report.signedVex.document, null, 2),
    'utf8'
  );
  fs.writeFileSync(
    path.join(outDir, 'vex.signed.json'),
    JSON.stringify(report.signedVex, null, 2),
    'utf8'
  );
  fs.writeFileSync(path.join(outDir, 'vexproof.pub'), report.signedVex.publicKeyPem, 'utf8');
  fs.writeFileSync(path.join(outDir, 'patch-pr.md'), report.patchPlan.prMarkdown, 'utf8');
}

function printHumanSummary(report: Awaited<ReturnType<typeof scanProject>>, outDir?: string) {
  const m = report.metrics;
  console.log('\n=== VEXProof Reachability & EU CRA Evidence Report ===');
  console.log(`Project:         ${report.projectName}@${report.projectVersion}`);
  console.log(`Target:          ${report.targetPath}`);
  console.log(`Intel Source:    ${m.intelMode.toUpperCase()} (OSV.dev + CISA KEV + FIRST EPSS)`);
  console.log(`Files Scanned:   ${report.astSummary.filesScanned} source files (${report.astSummary.entrypointsFound} entrypoints, ${report.astSummary.functionsMapped} functions)`);
  console.log(`Dependencies:    ${m.totalDependencies} total (${m.directDependencies} direct)`);
  console.log(`Vulnerabilities: ${m.totalVulnerabilities} matched from OSV.dev`);
  console.log(`  - AFFECTED (Reachable):         ${m.affectedCount}`);
  console.log(`  - UNDER INVESTIGATION (Eval):   ${m.underInvestigationCount}`);
  console.log(`  - NOT AFFECTED (Suppressed):    ${m.notAffectedCount} (${m.noiseReductionPercent}% triage noise eliminated)`);
  console.log(`Ed25519 Digest:  ${report.signedVex.canonicalDigestSha256}`);
  console.log(`Duration:        ${m.durationMs} ms\n`);

  for (const f of report.findings) {
    const id = f.vuln.cveId ?? f.vuln.id;
    const kevTag = f.vuln.inCisaKev ? ' [CISA-KEV]' : '';
    const epssTag = f.vuln.epssScore !== null ? ` [EPSS ${(f.vuln.epssScore * 100).toFixed(1)}%]` : '';
    console.log(
      `[${f.status.toUpperCase()} | ${f.craPriority}] ${id} (${f.vuln.packageName}@${f.vuln.installedVersion})${kevTag}${epssTag}`
    );
    console.log(`  Reason: ${f.rationale}`);
    if (f.callPath.length > 0) {
      console.log(`  CallPath: ${f.callPath.join(' -> ')}`);
    }
  }

  if (outDir) {
    console.log(`\nArtifacts exported to: ${path.resolve(outDir)}`);
    console.log('  - vex.signed.json (Ed25519 signed OpenVEX v0.2.0)');
    console.log('  - vex.json (OpenVEX document)');
    console.log('  - bom.json (CycloneDX 1.5 SBOM)');
    console.log('  - bom-vex.json (CycloneDX 1.5 VEX)');
    console.log('  - vexproof.pub (Ed25519 verification key)');
    console.log('  - patch-pr.md (Minimal upgrade plan)\n');
  }
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] ?? 'help';

  if (cmd === 'scan' || cmd === 'demo-real') {
    const target =
      cmd === 'demo-real'
        ? path.resolve(process.cwd(), 'examples', 'acme-eu-gateway')
        : args[1] ?? '.';
    const jsonFlag = args.includes('--json');
    const offlineOnly = args.includes('--offline');
    const outIdx = args.indexOf('--out');
    const outDir = outIdx !== -1 ? args[outIdx + 1] : path.join(process.cwd(), '.vexproof-out');

    const report = await scanProject(target, { offlineOnly });
    writeReportArtifacts(outDir, report);

    if (jsonFlag) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printHumanSummary(report, outDir);
    }
    return;
  }

  if (cmd === 'verify') {
    const vexPath = args[1];
    if (!vexPath) {
      console.error('Usage: vexproof verify <vex.signed.json> [--pub <vexproof.pub>]');
      process.exit(1);
    }
    const pubIdx = args.indexOf('--pub');
    const pubPem = pubIdx !== -1 && args[pubIdx + 1] ? fs.readFileSync(args[pubIdx + 1], 'utf8') : undefined;
    const bundle = JSON.parse(fs.readFileSync(vexPath, 'utf8')) as SignedVexBundle;
    const result = verifyVexBundle(bundle, pubPem);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 2);
  }

  console.log(`VEXProof CLI — Reachability-Verified SBOM & Signed OpenVEX Compiler

Usage:
  vexproof scan <path-or-github-url> [--out <dir>] [--offline] [--json]
  vexproof verify <vex.signed.json> [--pub <vexproof.pub>]
  vexproof demo-real [--out <dir>] [--json]
`);
}

main().catch((err) => {
  console.error('VEXProof Error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
