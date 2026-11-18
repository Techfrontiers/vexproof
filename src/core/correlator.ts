import type { AnalyzedProjectGraph } from './reachability-ast.js';
import type {
  CraPriority,
  DynamicHazard,
  ReachabilityFinding,
  VexStatus,
  VulnerabilityIntel,
} from './types.js';
import { matchSymbolRulesForVuln } from './vuln-symbols.js';

function computeCraPriority(
  status: VexStatus,
  vuln: VulnerabilityIntel
): CraPriority {
  if (status === 'not_affected') return 'SUPPRESSED_VEX';
  if (status === 'under_investigation') return 'VERIFY_DYNAMIC';
  if (
    vuln.inCisaKev ||
    vuln.severityLabel === 'CRITICAL' ||
    (vuln.epssScore !== null && vuln.epssScore >= 0.25)
  ) {
    return 'CRITICAL_24H';
  }
  return 'PATCH_PLANNED';
}

export function correlateReachabilityFindings(
  vulns: VulnerabilityIntel[],
  graph: AnalyzedProjectGraph,
  projectHasDirectDep: Set<string>
): ReachabilityFinding[] {
  const findings: ReachabilityFinding[] = [];
  const projectHazards: DynamicHazard[] = graph.summary.dynamicHazards;

  for (const vuln of vulns) {
    const pkgKey = vuln.packageName;
    const lowerPkgKey = pkgKey.toLowerCase();

    const reachableSymbolsMap =
      graph.reachableChainsByPkg.get(pkgKey) ??
      graph.reachableChainsByPkg.get(lowerPkgKey) ??
      new Map<string, string[]>();

    const allSites =
      graph.allCallSitesByPkg.get(pkgKey) ??
      graph.allCallSitesByPkg.get(lowerPkgKey) ??
      graph.summary.packagesImported[pkgKey] ??
      [];

    const reachableSites = allSites.filter((s) =>
      graph.reachableFunctionIds.has(s.callerFunction)
    );

    const ruleMatch = matchSymbolRulesForVuln(pkgKey, vuln.summary, vuln.details);

    // Case 1: Specific vulnerable symbol is explicitly called on a reachable path from an entrypoint
    if (ruleMatch.symbols.length > 0 && reachableSymbolsMap.size > 0) {
      const hitSymbols = ruleMatch.symbols.filter((sym) =>
        reachableSymbolsMap.has(sym) || reachableSymbolsMap.has('*')
      );
      if (hitSymbols.length > 0) {
        const firstHit = reachableSymbolsMap.get(hitSymbols[0]) ?? reachableSymbolsMap.get('*') ?? [];
        const matchingSites = reachableSites.filter(
          (s) => s.memberCalled === null || hitSymbols.includes(s.memberCalled) || s.memberCalled === '*'
        );
        findings.push({
          vuln,
          status: 'affected',
          craPriority: computeCraPriority('affected', vuln),
          confidence: 'deterministic',
          rationale: `Executable call path reaches vulnerable symbol(s) [${hitSymbols.join(', ')}] in ${pkgKey}@${vuln.installedVersion}${ruleMatch.note ? ` (${ruleMatch.note})` : ''}.`,
          matchedSymbols: hitSymbols,
          callPath: firstHit,
          callSites: matchingSites.length > 0 ? matchingSites : reachableSites,
          dynamicHazards: [],
        });
        continue;
      }

      // Package IS reachable via OTHER safe symbols — check if dynamic hazards exist
      if (projectHazards.length > 0) {
        findings.push({
          vuln,
          status: 'under_investigation',
          craPriority: 'VERIFY_DYNAMIC',
          confidence: 'dynamic-uncertain',
          rationale: `Static call sites in ${pkgKey} only invoke non-vulnerable symbol(s) [${Array.from(reachableSymbolsMap.keys()).join(', ')}], but dynamic code execution (${projectHazards.map((h) => h.kind).join(', ')}) prevents sound negative proof.`,
          matchedSymbols: [],
          callPath: Array.from(reachableSymbolsMap.values())[0] ?? [],
          callSites: reachableSites,
          dynamicHazards: projectHazards,
        });
        continue;
      }

      findings.push({
        vuln,
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        craPriority: 'SUPPRESSED_VEX',
        confidence: 'deterministic',
        rationale: `${pkgKey} is imported, but only unrelated symbol(s) [${Array.from(reachableSymbolsMap.keys()).join(', ')}] are called. None of the vulnerable symbol(s) [${ruleMatch.symbols.join(', ')}] appear on any reachable path, and 0 dynamic eval/require hazards were detected.`,
        matchedSymbols: [],
        callPath: [],
        callSites: reachableSites,
        dynamicHazards: [],
      });
      continue;
    }

    // Case 2: Package is imported on an active reachable path without a narrowed symbol rule
    if (reachableChainsByPkgHas(reachableSymbolsMap, reachableSites)) {
      const firstChain = Array.from(reachableSymbolsMap.values())[0] ?? [];
      findings.push({
        vuln,
        status: 'affected',
        craPriority: computeCraPriority('affected', vuln),
        confidence: 'symbol-heuristic',
        rationale: `Executable entrypoint calls into ${pkgKey}@${vuln.installedVersion} (${reachableSites.map((s) => `${s.file}:${s.line}`).slice(0, 3).join(', ')}).`,
        matchedSymbols: Array.from(reachableSymbolsMap.keys()),
        callPath: firstChain,
        callSites: reachableSites,
        dynamicHazards: [],
      });
      continue;
    }

    // Case 3: Package appears in dead/unreachable functions OR transitive lockfile only
    if (projectHazards.length > 0) {
      findings.push({
        vuln,
        status: 'under_investigation',
        craPriority: 'VERIFY_DYNAMIC',
        confidence: 'dynamic-uncertain',
        rationale: `No static call path reaches ${pkgKey}@${vuln.installedVersion}, but repository contains ${projectHazards.length} dynamic construct(s) (${projectHazards.map((h) => `${h.kind} at ${h.file}:${h.line}`).slice(0, 2).join('; ')}) that could load it at runtime.`,
        matchedSymbols: [],
        callPath: [],
        callSites: allSites,
        dynamicHazards: projectHazards,
      });
      continue;
    }

    const isTransitiveOnly = !projectHasDirectDep.has(lowerPkgKey) && allSites.length === 0;
    findings.push({
      vuln,
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      craPriority: 'SUPPRESSED_VEX',
      confidence: 'deterministic',
      rationale:
        allSites.length > 0
          ? `${pkgKey} call sites exist only in unreachable/dead functions (${allSites.map((s) => `${s.file}:${s.line}`).join(', ')}) with 0 paths from application entrypoints.`
          : isTransitiveOnly
            ? `Transitive dependency ${pkgKey}@${vuln.installedVersion} has zero static imports or reachable call paths in application code and 0 dynamic eval/require hazards.`
            : `Direct dependency ${pkgKey}@${vuln.installedVersion} is never imported or called in any analyzed runtime source file, and 0 dynamic eval/require hazards exist.`,
      matchedSymbols: [],
      callPath: [],
      callSites: allSites,
      dynamicHazards: [],
    });
  }

  // Sort actionable vulnerabilities first, then KEV/EPSS severity
  const priorityOrder: Record<CraPriority, number> = {
    CRITICAL_24H: 0,
    PATCH_PLANNED: 1,
    VERIFY_DYNAMIC: 2,
    SUPPRESSED_VEX: 3,
  };
  return findings.sort((a, b) => priorityOrder[a.craPriority] - priorityOrder[b.craPriority]);
}

function reachableChainsByPkgHas(
  reachableSymbolsMap: Map<string, string[]>,
  reachableSites: unknown[]
): boolean {
  return reachableSymbolsMap.size > 0 || reachableSites.length > 0;
}
