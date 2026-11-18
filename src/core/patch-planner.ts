import type { ReachabilityFinding, UpgradeAction, UpgradePatchPlan } from './types.js';

function compareSemverLoose(a: string, b: string): number {
  const pa = a.replace(/^v/, '').split(/[.\-]/).slice(0, 3).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.replace(/^v/, '').split(/[.\-]/).slice(0, 3).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

export function buildPatchPlan(
  findings: ReachabilityFinding[],
  rawPackageJson: Record<string, unknown> | null
): UpgradePatchPlan {
  const actionable = findings.filter((f) => f.status !== 'not_affected');
  const byPkg = new Map<string, UpgradeAction>();

  for (const f of actionable) {
    const fixedSorted = [...f.vuln.fixedVersions].sort(compareSemverLoose);
    // Pick highest required fixed version across vulnerabilities on the same package
    const bestFix = fixedSorted[fixedSorted.length - 1];
    if (!bestFix) continue;

    const key = `${f.vuln.ecosystem}:${f.vuln.packageName}`;
    const existing = byPkg.get(key);
    const vulnLabel = f.vuln.cveId ?? f.vuln.id;

    if (!existing) {
      byPkg.set(key, {
        packageName: f.vuln.packageName,
        ecosystem: f.vuln.ecosystem,
        currentVersion: f.vuln.installedVersion,
        targetVersion: bestFix,
        triggeredByVuls: [vulnLabel],
        reasons: [`[${f.craPriority}] ${f.rationale}`],
        npmCommand:
          f.vuln.ecosystem === 'npm'
            ? `npm install ${f.vuln.packageName}@${bestFix}`
            : f.vuln.ecosystem === 'PyPI'
              ? `pip install "${f.vuln.packageName}>=${bestFix}"`
              : `go get ${f.vuln.packageName}@v${bestFix}`,
      });
    } else {
      if (compareSemverLoose(bestFix, existing.targetVersion) > 0) {
        existing.targetVersion = bestFix;
        existing.npmCommand =
          f.vuln.ecosystem === 'npm'
            ? `npm install ${f.vuln.packageName}@${bestFix}`
            : existing.npmCommand;
      }
      if (!existing.triggeredByVuls.includes(vulnLabel)) {
        existing.triggeredByVuls.push(vulnLabel);
      }
      existing.reasons.push(`[${f.craPriority}] ${f.rationale}`);
    }
  }

  const actions = Array.from(byPkg.values());
  const diffLines: string[] = ['--- a/package.json', '+++ b/package.json', '   "dependencies": {'];

  const deps = (rawPackageJson?.dependencies as Record<string, string>) ?? {};
  for (const act of actions) {
    if (act.ecosystem !== 'npm') continue;
    const oldVal = deps[act.packageName] ?? `^${act.currentVersion}`;
    diffLines.push(`-    "${act.packageName}": "${oldVal}",`);
    diffLines.push(`+    "${act.packageName}": "^${act.targetVersion}",`);
  }
  diffLines.push('   }');

  const suppressedCount = findings.filter((f) => f.status === 'not_affected').length;
  const prMarkdown = [
    `## VEXProof EU CRA Reachable Vulnerability Remediation PR`,
    ``,
    `- **Actionable Packages Patched:** ${actions.length}`,
    `- **Unreachable CVEs Suppressed via Signed OpenVEX:** ${suppressedCount}`,
    ``,
    `### Changes`,
    ...actions.map(
      (a) =>
        `- Upgrade \`${a.packageName}\` \`${a.currentVersion}\` -> \`${a.targetVersion}\` (Addresses ${a.triggeredByVuls.join(', ')})`
    ),
    ``,
    `### CLI Command`,
    '```bash',
    actions.map((a) => a.npmCommand).join(' && ') || '# No reachable package upgrades required',
    '```',
  ].join('\n');

  return {
    actions,
    packageJsonDiff: actions.some((a) => a.ecosystem === 'npm')
      ? diffLines.join('\n')
      : '# No direct npm dependency manifest changes required.',
    prMarkdown,
  };
}
