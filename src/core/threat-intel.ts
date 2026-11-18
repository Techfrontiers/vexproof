import fs from 'node:fs';
import path from 'node:path';
import type { ParsedDependency, VulnerabilityIntel } from './types.js';

interface OsvQueryBatchResponse {
  results?: Array<{
    vulns?: Array<{ id: string; modified?: string }>;
  }>;
}

interface OsvVulnDetail {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  database_specific?: {
    severity?: string;
    cvss_score?: number;
  };
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references?: Array<{ type?: string; url?: string }>;
}

interface CisaKevCatalog {
  vulnerabilities?: Array<{
    cveID: string;
    dueDate?: string;
  }>;
}

interface FirstEpssResponse {
  data?: Array<{
    cve: string;
    epss: string;
    percentile: string;
  }>;
}

const DEFAULT_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

function getCacheDir(baseDir?: string): string {
  const dir = path.join(baseDir ?? process.cwd(), '.vexproof-cache');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function readCache<T>(cacheFile: string, ttlMs = DEFAULT_TTL_MS): T | null {
  try {
    if (!fs.existsSync(cacheFile)) return null;
    const stat = fs.statSync(cacheFile);
    if (Date.now() - stat.mtimeMs > ttlMs) return null;
    return JSON.parse(fs.readFileSync(cacheFile, 'utf8')) as T;
  } catch {
    return null;
  }
}

function writeCache(cacheFile: string, data: unknown): void {
  try {
    fs.writeFileSync(cacheFile, JSON.stringify(data), 'utf8');
  } catch {
    // Non-fatal cache write error
  }
}

function normalizeSeverity(detail: OsvVulnDetail): {
  label: VulnerabilityIntel['severityLabel'];
  cvssScore: number | null;
} {
  const dbSev = detail.database_specific?.severity?.toUpperCase();
  let label: VulnerabilityIntel['severityLabel'] = 'UNKNOWN';
  if (dbSev === 'CRITICAL' || dbSev === 'HIGH' || dbSev === 'MODERATE' || dbSev === 'MEDIUM' || dbSev === 'LOW') {
    label = dbSev === 'MODERATE' ? 'MEDIUM' : dbSev;
  }
  const cvssScore =
    typeof detail.database_specific?.cvss_score === 'number'
      ? detail.database_specific.cvss_score
      : null;

  if (label === 'UNKNOWN' && cvssScore !== null) {
    if (cvssScore >= 9.0) label = 'CRITICAL';
    else if (cvssScore >= 7.0) label = 'HIGH';
    else if (cvssScore >= 4.0) label = 'MEDIUM';
    else label = 'LOW';
  }

  return { label, cvssScore };
}

function extractFixedVersions(detail: OsvVulnDetail, packageName: string): string[] {
  const fixed = new Set<string>();
  for (const aff of detail.affected ?? []) {
    if (aff.package?.name && aff.package.name.toLowerCase() !== packageName.toLowerCase()) {
      continue;
    }
    for (const range of aff.ranges ?? []) {
      for (const evt of range.events ?? []) {
        if (evt.fixed) fixed.add(evt.fixed);
      }
    }
  }
  return Array.from(fixed);
}

async function fetchJsonWithTimeout<T>(url: string, init?: RequestInit, timeoutMs = 15000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${url}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchOsvVulnDetail(
  vulnId: string,
  cacheDir: string,
  offlineOnly: boolean
): Promise<{ detail: OsvVulnDetail; source: 'live' | 'cache' }> {
  const safeId = vulnId.replace(/[^A-Za-z0-9._-]/g, '_');
  const cacheFile = path.join(cacheDir, `osv-vuln-${safeId}.json`);
  const cached = readCache<OsvVulnDetail>(cacheFile, offlineOnly ? Number.MAX_SAFE_INTEGER : DEFAULT_TTL_MS);
  if (cached) {
    return { detail: cached, source: 'cache' };
  }
  if (offlineOnly) {
    throw new Error(`Offline mode enabled and OSV cache missing for ${vulnId}`);
  }
  const detail = await fetchJsonWithTimeout<OsvVulnDetail>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`);
  writeCache(cacheFile, detail);
  return { detail, source: 'live' };
}

async function fetchCisaKevMap(
  cacheDir: string,
  offlineOnly: boolean
): Promise<Map<string, string | null>> {
  const cacheFile = path.join(cacheDir, 'cisa-kev.json');
  const cached = readCache<CisaKevCatalog>(cacheFile, offlineOnly ? Number.MAX_SAFE_INTEGER : DEFAULT_TTL_MS);
  let catalog: CisaKevCatalog | null = cached;

  if (!catalog && !offlineOnly) {
    try {
      catalog = await fetchJsonWithTimeout<CisaKevCatalog>(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        undefined,
        15000
      );
      writeCache(cacheFile, catalog);
    } catch {
      // Fallback to stale cache if live CISA endpoint times out
      catalog = readCache<CisaKevCatalog>(cacheFile, Number.MAX_SAFE_INTEGER);
    }
  }

  const map = new Map<string, string | null>();
  for (const item of catalog?.vulnerabilities ?? []) {
    if (item.cveID) {
      map.set(item.cveID.toUpperCase(), item.dueDate ?? null);
    }
  }
  return map;
}

async function fetchEpssMap(
  cves: string[],
  cacheDir: string,
  offlineOnly: boolean
): Promise<Map<string, { score: number; percentile: number }>> {
  const map = new Map<string, { score: number; percentile: number }>();
  const unique = Array.from(new Set(cves.map((c) => c.toUpperCase()))).filter((c) => c.startsWith('CVE-'));
  if (unique.length === 0) return map;

  const missing: string[] = [];
  for (const cve of unique) {
    const cacheFile = path.join(cacheDir, `epss-${cve}.json`);
    const cached = readCache<{ score: number; percentile: number }>(
      cacheFile,
      offlineOnly ? Number.MAX_SAFE_INTEGER : DEFAULT_TTL_MS
    );
    if (cached) {
      map.set(cve, cached);
    } else {
      missing.push(cve);
    }
  }

  if (missing.length > 0 && !offlineOnly) {
    for (let i = 0; i < missing.length; i += 40) {
      const slice = missing.slice(i, i + 40);
      try {
        const resp = await fetchJsonWithTimeout<FirstEpssResponse>(
          `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(slice.join(','))}`,
          undefined,
          12000
        );
        for (const row of resp.data ?? []) {
          const entry = {
            score: Number.parseFloat(row.epss),
            percentile: Number.parseFloat(row.percentile),
          };
          if (!Number.isNaN(entry.score)) {
            const key = row.cve.toUpperCase();
            map.set(key, entry);
            writeCache(path.join(cacheDir, `epss-${key}.json`), entry);
          }
        }
      } catch {
        // Non-fatal: continue even if FIRST EPSS API is unreachable
      }
    }
  }

  return map;
}

export async function correlateThreatIntel(
  dependencies: ParsedDependency[],
  options?: { cacheBaseDir?: string; offlineOnly?: boolean }
): Promise<VulnerabilityIntel[]> {
  if (dependencies.length === 0) return [];
  const cacheDir = getCacheDir(options?.cacheBaseDir);
  const offlineOnly = Boolean(options?.offlineOnly);

  // Deduplicate dependency queries by (ecosystem, name, version)
  const uniqueDeps = Array.from(
    new Map(dependencies.map((d) => [`${d.ecosystem}:${d.name}@${d.version}`, d])).values()
  );

  const batchHashKey = uniqueDeps
    .map((d) => `${d.ecosystem}:${d.name}@${d.version}`)
    .sort()
    .join('|')
    .slice(0, 120)
    .replace(/[^A-Za-z0-9._-]/g, '_');

  const batchQueries = uniqueDeps.map((dep) => ({
    package: { name: dep.name, ecosystem: dep.ecosystem },
    version: dep.version,
  }));

  let batchResults: Array<{ vulns?: Array<{ id: string }> }> = [];
  let batchSource: 'live' | 'cache' = 'live';

  const batchCacheFile = path.join(cacheDir, `osv-batch-${Buffer.from(batchHashKey).toString('hex').slice(0, 24)}.json`);
  const cachedBatch = readCache<OsvQueryBatchResponse>(
    batchCacheFile,
    offlineOnly ? Number.MAX_SAFE_INTEGER : DEFAULT_TTL_MS
  );

  if (cachedBatch?.results) {
    batchResults = cachedBatch.results;
    batchSource = 'cache';
  } else if (!offlineOnly) {
    // OSV querybatch supports up to 1000 queries per request
    const allResults: Array<{ vulns?: Array<{ id: string }> }> = [];
    for (let i = 0; i < batchQueries.length; i += 250) {
      const chunk = batchQueries.slice(i, i + 250);
      const resp = await fetchJsonWithTimeout<OsvQueryBatchResponse>(
        'https://api.osv.dev/v1/querybatch',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries: chunk }),
        },
        20000
      );
      allResults.push(...(resp.results ?? chunk.map(() => ({ vulns: [] }))));
    }
    batchResults = allResults;
    writeCache(batchCacheFile, { results: batchResults });
  } else {
    throw new Error('Offline mode enabled and no cached OSV batch response exists for these dependencies.');
  }

  // Gather unique vuln IDs linked to dependencies
  const depVulnPairs: Array<{ dep: ParsedDependency; vulnId: string }> = [];
  const uniqueVulnIds = new Set<string>();

  uniqueDeps.forEach((dep, idx) => {
    const vulns = batchResults[idx]?.vulns ?? [];
    for (const v of vulns) {
      depVulnPairs.push({ dep, vulnId: v.id });
      uniqueVulnIds.add(v.id);
    }
  });

  if (depVulnPairs.length === 0) return [];

  // Fetch OSV details concurrently (bounded concurrency of 8)
  const detailMap = new Map<string, { detail: OsvVulnDetail; source: 'live' | 'cache' }>();
  const vulnIdList = Array.from(uniqueVulnIds);
  for (let i = 0; i < vulnIdList.length; i += 8) {
    const chunk = vulnIdList.slice(i, i + 8);
    const fetched = await Promise.all(
      chunk.map(async (id) => {
        const res = await fetchOsvVulnDetail(id, cacheDir, offlineOnly);
        return [id, res] as const;
      })
    );
    for (const [id, res] of fetched) {
      detailMap.set(id, res);
    }
  }

  // Deduplicate by primary CVE alias per package so GHSA + CVE duplicates don't double-count the exact same flaw
  const cveCandidates: string[] = [];
  for (const [, { detail }] of detailMap) {
    const cve = detail.id.startsWith('CVE-')
      ? detail.id
      : (detail.aliases ?? []).find((a) => a.startsWith('CVE-')) ?? null;
    if (cve) cveCandidates.push(cve);
  }

  const [kevMap, epssMap] = await Promise.all([
    fetchCisaKevMap(cacheDir, offlineOnly),
    fetchEpssMap(cveCandidates, cacheDir, offlineOnly),
  ]);

  const seenPackageCve = new Set<string>();
  const results: VulnerabilityIntel[] = [];

  for (const { dep, vulnId } of depVulnPairs) {
    const item = detailMap.get(vulnId);
    if (!item) continue;
    const { detail, source } = item;
    const aliases = detail.aliases ?? [];
    const cveId = detail.id.startsWith('CVE-')
      ? detail.id
      : aliases.find((a) => a.startsWith('CVE-')) ?? null;

    const dedupeKey = `${dep.ecosystem}:${dep.name}@${dep.version}:${cveId ?? detail.id}`;
    if (seenPackageCve.has(dedupeKey)) continue;
    seenPackageCve.add(dedupeKey);

    const { label, cvssScore } = normalizeSeverity(detail);
    const fixedVersions = extractFixedVersions(detail, dep.name);
    const inCisaKev = cveId ? kevMap.has(cveId.toUpperCase()) : false;
    const kevDueDate = cveId ? kevMap.get(cveId.toUpperCase()) ?? null : null;
    const epss = cveId ? epssMap.get(cveId.toUpperCase()) ?? null : null;

    results.push({
      id: detail.id,
      aliases,
      cveId,
      packageName: dep.name,
      ecosystem: dep.ecosystem,
      installedVersion: dep.version,
      purl: dep.purl,
      summary: detail.summary ?? detail.details?.slice(0, 180) ?? `Vulnerability ${detail.id} in ${dep.name}`,
      details: detail.details ?? '',
      severityLabel: label,
      cvssScore,
      fixedVersions,
      inCisaKev,
      kevDueDate,
      epssScore: epss ? epss.score : null,
      epssPercentile: epss ? epss.percentile : null,
      intelSource: batchSource === 'live' || source === 'live' ? 'live' : 'cache',
      references: (detail.references ?? [])
        .map((r) => r.url)
        .filter((u): u is string => Boolean(u))
        .slice(0, 4),
    });
  }

  return results;
}
