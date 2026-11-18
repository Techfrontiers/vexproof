import crypto from 'node:crypto';
import type {
  CycloneDxSbom,
  OpenVexDocument,
  OpenVexStatement,
  ReachabilityFinding,
  SignedVexBundle,
} from './types.js';

export function canonicalJsonStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJsonStringify(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJsonStringify(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

export function generateEd25519KeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

export function compileOpenVexDocument(
  projectName: string,
  projectVersion: string,
  findings: ReachabilityFinding[]
): OpenVexDocument {
  const now = new Date().toISOString();
  const productUri = `pkg:application/${encodeURIComponent(projectName)}@${projectVersion}`;

  const statements: OpenVexStatement[] = findings.map((f) => {
    const vulnId = f.vuln.cveId ?? f.vuln.id;
    const base: OpenVexStatement = {
      vulnerability: {
        '@id': `https://osv.dev/vulnerability/${encodeURIComponent(f.vuln.id)}`,
        name: vulnId,
        description: f.vuln.summary,
        aliases: Array.from(new Set([f.vuln.id, ...f.vuln.aliases])),
      },
      products: [
        {
          '@id': productUri,
          subcomponents: [{ '@id': f.vuln.purl }],
        },
      ],
      status: f.status,
      status_notes: `${f.rationale}${
        f.callPath.length > 0 ? ` | CallPath: ${f.callPath.join(' -> ')}` : ''
      } | Intel: ${f.vuln.intelSource.toUpperCase()}, KEV=${f.vuln.inCisaKev}, EPSS=${f.vuln.epssScore ?? 'N/A'}`,
      timestamp: now,
    };

    if (f.status === 'not_affected') {
      base.justification = f.justification ?? 'vulnerable_code_not_in_execute_path';
      base.impact_statement = `AST call-graph reachability analysis proved ${vulnId} in ${f.vuln.packageName}@${f.vuln.installedVersion} is unreachable from runtime entrypoints.`;
    } else if (f.status === 'affected') {
      const targetFix = f.vuln.fixedVersions[0];
      base.action_statement = targetFix
        ? `Upgrade ${f.vuln.packageName} from ${f.vuln.installedVersion} to >= ${targetFix} and re-verify call path.`
        : `Isolate or mitigate reachable call path to ${f.vuln.packageName} (${f.matchedSymbols.join(', ') || 'package call'}).`;
    } else {
      base.action_statement =
        'Audit dynamic eval/require call sites flagged by VEXProof before clearing EU CRA compliance gate.';
    }

    return base;
  });

  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${crypto.randomUUID()}`,
    author: 'VEXProof Automated Reachability Compiler',
    role: 'EU CRA Security Evidence Generator',
    timestamp: now,
    version: 1,
    tooling: 'VEXProof/1.0.0 (TypeScript-AST + OSV.dev + CISA-KEV + FIRST-EPSS)',
    statements,
  };
}

export function signOpenVexDocument(
  document: OpenVexDocument,
  keyPair?: { publicKeyPem: string; privateKeyPem: string }
): SignedVexBundle {
  const keys = keyPair ?? generateEd25519KeyPair();
  const canonical = canonicalJsonStringify(document);
  const canonicalDigestSha256 = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), keys.privateKeyPem);

  return {
    algorithm: 'Ed25519',
    canonicalDigestSha256,
    signatureBase64: signature.toString('base64'),
    publicKeyPem: keys.publicKeyPem,
    signedAt: new Date().toISOString(),
    document,
  };
}

export function verifyVexBundle(
  bundle: SignedVexBundle,
  overridePublicKeyPem?: string
): {
  valid: boolean;
  recomputedSha256: string;
  claimedSha256: string;
  statementCount: number;
  reason: string;
} {
  try {
    const pubPem = overridePublicKeyPem ?? bundle.publicKeyPem;
    const canonical = canonicalJsonStringify(bundle.document);
    const recomputedSha256 = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');

    if (recomputedSha256 !== bundle.canonicalDigestSha256) {
      return {
        valid: false,
        recomputedSha256,
        claimedSha256: bundle.canonicalDigestSha256,
        statementCount: bundle.document?.statements?.length ?? 0,
        reason: 'SHA-256 digest mismatch: OpenVEX payload was altered after signing.',
      };
    }

    const sigOk = crypto.verify(
      null,
      Buffer.from(canonical, 'utf8'),
      pubPem,
      Buffer.from(bundle.signatureBase64, 'base64')
    );

    return {
      valid: sigOk,
      recomputedSha256,
      claimedSha256: bundle.canonicalDigestSha256,
      statementCount: bundle.document?.statements?.length ?? 0,
      reason: sigOk
        ? 'Ed25519 cryptographic signature and canonical SHA-256 digest verified.'
        : 'Ed25519 signature verification failed against public key.',
    };
  } catch (err) {
    return {
      valid: false,
      recomputedSha256: '',
      claimedSha256: bundle?.canonicalDigestSha256 ?? '',
      statementCount: 0,
      reason: err instanceof Error ? err.message : 'Malformed SignedVexBundle payload',
    };
  }
}

export function compileCycloneDxVex(
  sbom: CycloneDxSbom,
  findings: ReachabilityFinding[]
): Record<string, unknown> {
  return {
    ...sbom,
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    metadata: {
      ...sbom.metadata,
      timestamp: new Date().toISOString(),
    },
    vulnerabilities: findings.map((f) => ({
      id: f.vuln.cveId ?? f.vuln.id,
      source: {
        name: 'OSV.dev',
        url: `https://osv.dev/vulnerability/${encodeURIComponent(f.vuln.id)}`,
      },
      ratings: [
        {
          severity: f.vuln.severityLabel.toLowerCase(),
          ...(f.vuln.cvssScore !== null ? { score: f.vuln.cvssScore, method: 'CVSSv3' } : {}),
        },
      ],
      description: f.vuln.summary,
      analysis: {
        state:
          f.status === 'affected'
            ? 'exploitable'
            : f.status === 'not_affected'
              ? 'not_affected'
              : 'in_triage',
        ...(f.justification ? { justification: f.justification } : {}),
        detail: f.rationale,
      },
      affects: [{ ref: f.vuln.purl }],
    })),
  };
}
