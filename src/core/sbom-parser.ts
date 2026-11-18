import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { CycloneDxComponent, CycloneDxSbom, Ecosystem, ParsedDependency } from './types.js';

export interface ParsedProjectManifest {
  projectName: string;
  projectVersion: string;
  dependencies: ParsedDependency[];
  rawPackageJson: Record<string, unknown> | null;
}

export function buildPurl(ecosystem: Ecosystem, name: string, version: string): string {
  const cleanVersion = version.replace(/^[v^~>=<]+/, '').trim() || '0.0.0';
  if (ecosystem === 'npm') {
    if (name.startsWith('@')) {
      const [scope, pkg] = name.split('/');
      return `pkg:npm/%40${scope.slice(1)}/${pkg}@${cleanVersion}`;
    }
    return `pkg:npm/${name}@${cleanVersion}`;
  }
  if (ecosystem === 'PyPI') {
    return `pkg:pypi/${name.toLowerCase()}@${cleanVersion}`;
  }
  return `pkg:golang/${name}@${cleanVersion}`;
}

function normalizeVersion(raw: string): string {
  return raw.replace(/^[~^=<>v\s]+/, '').split(/\s+/)[0] || raw.trim();
}

function parseNpmLockfile(rootDir: string, pkgJson: Record<string, unknown> | null): ParsedDependency[] {
  const lockPath = path.join(rootDir, 'package-lock.json');
  if (!fs.existsSync(lockPath)) {
    return [];
  }

  const raw = JSON.parse(fs.readFileSync(lockPath, 'utf8')) as {
    lockfileVersion?: number;
    packages?: Record<string, { version?: string; dev?: boolean; optional?: boolean }>;
    dependencies?: Record<
      string,
      {
        version?: string;
        dev?: boolean;
        optional?: boolean;
        dependencies?: Record<string, unknown>;
      }
    >;
  };

  const directDeps = new Set<string>([
    ...Object.keys((pkgJson?.dependencies as Record<string, string>) ?? {}),
    ...Object.keys((pkgJson?.optionalDependencies as Record<string, string>) ?? {}),
  ]);
  const directDevDeps = new Set<string>(
    Object.keys((pkgJson?.devDependencies as Record<string, string>) ?? {})
  );

  const seen = new Map<string, ParsedDependency>();

  if (raw.packages && typeof raw.packages === 'object') {
    for (const [pkgPath, entry] of Object.entries(raw.packages)) {
      if (!pkgPath || pkgPath === '' || !entry.version) continue;
      // Extract innermost package name from node_modules/... path
      const marker = 'node_modules/';
      const lastIdx = pkgPath.lastIndexOf(marker);
      if (lastIdx === -1) continue;
      const name = pkgPath.slice(lastIdx + marker.length);
      if (!name) continue;
      const isDirect = !pkgPath.slice(0, lastIdx).includes(marker) && (directDeps.has(name) || directDevDeps.has(name));
      const scope: ParsedDependency['scope'] = entry.dev || directDevDeps.has(name)
        ? 'dev'
        : entry.optional
          ? 'optional'
          : 'required';
      const key = `npm:${name}@${entry.version}`;
      if (!seen.has(key)) {
        seen.set(key, {
          ecosystem: 'npm',
          name,
          version: entry.version,
          purl: buildPurl('npm', name, entry.version),
          scope,
          direct: isDirect,
          sourceFile: 'package-lock.json',
        });
      }
    }
  } else if (raw.dependencies && typeof raw.dependencies === 'object') {
    const walk = (deps: typeof raw.dependencies, depth: number) => {
      if (!deps) return;
      for (const [name, meta] of Object.entries(deps)) {
        if (!meta?.version) continue;
        const scope: ParsedDependency['scope'] = meta.dev ? 'dev' : meta.optional ? 'optional' : 'required';
        const key = `npm:${name}@${meta.version}`;
        if (!seen.has(key)) {
          seen.set(key, {
            ecosystem: 'npm',
            name,
            version: meta.version,
            purl: buildPurl('npm', name, meta.version),
            scope,
            direct: depth === 0 || directDeps.has(name),
            sourceFile: 'package-lock.json',
          });
        }
        if (meta.dependencies) {
          walk(meta.dependencies as typeof raw.dependencies, depth + 1);
        }
      }
    };
    walk(raw.dependencies, 0);
  }

  return Array.from(seen.values());
}

function parsePackageJsonFallback(rootDir: string, pkgJson: Record<string, unknown> | null): ParsedDependency[] {
  if (!pkgJson) return [];
  const results: ParsedDependency[] = [];
  const groups: Array<[Record<string, string> | undefined, ParsedDependency['scope']]> = [
    [pkgJson.dependencies as Record<string, string> | undefined, 'required'],
    [pkgJson.optionalDependencies as Record<string, string> | undefined, 'optional'],
    [pkgJson.devDependencies as Record<string, string> | undefined, 'dev'],
  ];

  for (const [group, scope] of groups) {
    if (!group) continue;
    for (const [name, rawVer] of Object.entries(group)) {
      const version = normalizeVersion(rawVer);
      if (!version || version === '*') continue;
      results.push({
        ecosystem: 'npm',
        name,
        version,
        purl: buildPurl('npm', name, version),
        scope,
        direct: true,
        sourceFile: 'package.json',
      });
    }
  }
  return results;
}

function parseRequirementsTxt(rootDir: string): ParsedDependency[] {
  const reqPath = path.join(rootDir, 'requirements.txt');
  if (!fs.existsSync(reqPath)) return [];
  const lines = fs.readFileSync(reqPath, 'utf8').split(/\r?\n/);
  const deps: ParsedDependency[] = [];
  for (const rawLine of lines) {
    const line = rawLine.split('#')[0].trim();
    if (!line || line.startsWith('-')) continue;
    const match = line.match(/^([A-Za-z0-9_.\-]+)\s*(?:==|~=|>=|<=)\s*([A-Za-z0-9_.\-+]+)/);
    if (!match) continue;
    const [, name, version] = match;
    deps.push({
      ecosystem: 'PyPI',
      name,
      version,
      purl: buildPurl('PyPI', name, version),
      scope: 'required',
      direct: true,
      sourceFile: 'requirements.txt',
    });
  }
  return deps;
}

function parseGoMod(rootDir: string): ParsedDependency[] {
  const goModPath = path.join(rootDir, 'go.mod');
  if (!fs.existsSync(goModPath)) return [];
  const content = fs.readFileSync(goModPath, 'utf8');
  const deps: ParsedDependency[] = [];
  const lineRegex = /^\s*([^\s/]+\/[^\s]+)\s+(v[^\s]+)/gm;
  let match: RegExpExecArray | null;
  while ((match = lineRegex.exec(content)) !== null) {
    const [, name, rawVer] = match;
    const indirect = content.slice(match.index, match.index + match[0].length + 25).includes('// indirect');
    const version = rawVer.replace(/^v/, '');
    deps.push({
      ecosystem: 'Go',
      name,
      version,
      purl: buildPurl('Go', name, version),
      scope: 'required',
      direct: !indirect,
      sourceFile: 'go.mod',
    });
  }
  return deps;
}

export function parseProjectManifests(rootDir: string): ParsedProjectManifest {
  const pkgPath = path.join(rootDir, 'package.json');
  const rawPackageJson = fs.existsSync(pkgPath)
    ? (JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as Record<string, unknown>)
    : null;

  const projectName =
    (typeof rawPackageJson?.name === 'string' && rawPackageJson.name.trim()) ||
    path.basename(path.resolve(rootDir));
  const projectVersion =
    (typeof rawPackageJson?.version === 'string' && rawPackageJson.version.trim()) || '1.0.0';

  const lockDeps = parseNpmLockfile(rootDir, rawPackageJson);
  const npmDeps = lockDeps.length > 0 ? lockDeps : parsePackageJsonFallback(rootDir, rawPackageJson);
  const pyDeps = parseRequirementsTxt(rootDir);
  const goDeps = parseGoMod(rootDir);

  return {
    projectName,
    projectVersion,
    dependencies: [...npmDeps, ...pyDeps, ...goDeps],
    rawPackageJson,
  };
}

export function generateCycloneDxSbom(
  projectName: string,
  projectVersion: string,
  dependencies: ParsedDependency[]
): CycloneDxSbom {
  const components: CycloneDxComponent[] = dependencies.map((dep) => ({
    type: 'library',
    'bom-ref': dep.purl,
    name: dep.name,
    version: dep.version,
    purl: dep.purl,
    scope: dep.scope === 'dev' ? 'optional' : 'required',
    properties: [
      { name: 'vexproof:ecosystem', value: dep.ecosystem },
      { name: 'vexproof:direct', value: String(dep.direct) },
      { name: 'vexproof:sourceFile', value: dep.sourceFile },
    ],
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'VEXProof',
          name: 'vexproof-sbom-compiler',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        'bom-ref': `pkg:application/${encodeURIComponent(projectName)}@${projectVersion}`,
        name: projectName,
        version: projectVersion,
      },
    },
    components,
  };
}
