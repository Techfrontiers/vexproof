export type Ecosystem = 'npm' | 'PyPI' | 'Go';

export interface ParsedDependency {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  purl: string;
  scope: 'required' | 'optional' | 'dev';
  direct: boolean;
  sourceFile: string;
}

export interface CycloneDxComponent {
  type: 'library';
  'bom-ref': string;
  name: string;
  version: string;
  purl: string;
  scope: 'required' | 'optional' | 'excluded';
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDxSbom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component: {
      type: 'application';
      'bom-ref': string;
      name: string;
      version: string;
    };
  };
  components: CycloneDxComponent[];
}

export interface VulnerabilityIntel {
  id: string;
  aliases: string[];
  cveId: string | null;
  packageName: string;
  ecosystem: Ecosystem;
  installedVersion: string;
  purl: string;
  summary: string;
  details: string;
  severityLabel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssScore: number | null;
  fixedVersions: string[];
  inCisaKev: boolean;
  kevDueDate: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  intelSource: 'live' | 'cache';
  references: string[];
}

export interface CallSite {
  file: string;
  line: number;
  column: number;
  callerFunction: string;
  importedAs: string;
  memberCalled: string | null;
  snippet: string;
}

export interface DynamicHazard {
  file: string;
  line: number;
  column: number;
  kind: 'eval' | 'new-function' | 'dynamic-require' | 'dynamic-import' | 'reflect-call';
  snippet: string;
}

export interface CallGraphNode {
  id: string;
  label: string;
  kind: 'entrypoint' | 'function' | 'external-symbol' | 'dynamic-hazard';
  file: string;
  line: number;
}

export interface CallGraphEdge {
  from: string;
  to: string;
  kind: 'calls' | 'imports' | 'hazard';
}

export interface AstAnalysisSummary {
  filesScanned: number;
  entrypointsFound: number;
  functionsMapped: number;
  edgesMapped: number;
  dynamicHazards: DynamicHazard[];
  packagesImported: Record<string, CallSite[]>;
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

export type VexStatus = 'affected' | 'not_affected' | 'under_investigation';

export type OpenVexJustification =
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist';

export type CraPriority = 'CRITICAL_24H' | 'PATCH_PLANNED' | 'VERIFY_DYNAMIC' | 'SUPPRESSED_VEX';

export interface ReachabilityFinding {
  vuln: VulnerabilityIntel;
  status: VexStatus;
  justification?: OpenVexJustification;
  craPriority: CraPriority;
  confidence: 'deterministic' | 'symbol-heuristic' | 'dynamic-uncertain';
  rationale: string;
  matchedSymbols: string[];
  callPath: string[];
  callSites: CallSite[];
  dynamicHazards: DynamicHazard[];
}

export interface OpenVexStatement {
  vulnerability: {
    '@id': string;
    name: string;
    description: string;
    aliases: string[];
  };
  products: Array<{
    '@id': string;
    subcomponents: Array<{ '@id': string }>;
  }>;
  status: VexStatus;
  justification?: OpenVexJustification;
  impact_statement?: string;
  action_statement?: string;
  status_notes: string;
  timestamp: string;
}

export interface OpenVexDocument {
  '@context': 'https://openvex.dev/ns/v0.2.0';
  '@id': string;
  author: string;
  role: string;
  timestamp: string;
  version: number;
  tooling: string;
  statements: OpenVexStatement[];
}

export interface SignedVexBundle {
  algorithm: 'Ed25519';
  canonicalDigestSha256: string;
  signatureBase64: string;
  publicKeyPem: string;
  signedAt: string;
  document: OpenVexDocument;
}

export interface UpgradeAction {
  packageName: string;
  ecosystem: Ecosystem;
  currentVersion: string;
  targetVersion: string;
  triggeredByVuls: string[];
  reasons: string[];
  npmCommand: string;
}

export interface UpgradePatchPlan {
  actions: UpgradeAction[];
  packageJsonDiff: string;
  prMarkdown: string;
}

export interface ScanMetrics {
  totalDependencies: number;
  directDependencies: number;
  totalVulnerabilities: number;
  affectedCount: number;
  notAffectedCount: number;
  underInvestigationCount: number;
  noiseReductionPercent: number;
  durationMs: number;
  intelMode: 'live' | 'cache' | 'mixed';
}

export interface ScanReport {
  projectName: string;
  projectVersion: string;
  targetPath: string;
  scannedAt: string;
  metrics: ScanMetrics;
  dependencies: ParsedDependency[];
  sbom: CycloneDxSbom;
  astSummary: AstAnalysisSummary;
  findings: ReachabilityFinding[];
  signedVex: SignedVexBundle;
  cyclonedxVex: Record<string, unknown>;
  patchPlan: UpgradePatchPlan;
}
