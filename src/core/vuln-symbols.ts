export interface VulnerableSymbolRule {
  /** Vulnerable exported methods or properties. Empty array means package-level import/invocation triggers vulnerability. */
  symbols: string[];
  /** Keywords in OSV summary/details that narrow this rule to a specific vulnerability class. */
  summaryHints?: string[];
  reason: string;
}

/**
 * Curated symbol-level vulnerability knowledge base for widely deployed open-source libraries.
 * Enables deterministic symbol-level provenance beyond coarse package-name matching.
 */
export const VULNERABLE_SYMBOL_RULES: Record<string, VulnerableSymbolRule[]> = {
  lodash: [
    {
      symbols: ['template'],
      summaryHints: ['template', 'command injection', 'arbitrary code'],
      reason: 'Command/code injection via lodash.template variable/sourceURL interpolation',
    },
    {
      symbols: ['merge', 'mergeWith', 'defaultsDeep', 'zipObjectDeep', 'set', 'setWith', 'unset', 'omit', 'pullAt'],
      summaryHints: ['prototype pollution', 'unset', 'omit', 'pullat'],
      reason: 'Prototype pollution in object merge/deep path mutation helpers',
    },
    {
      symbols: ['trim', 'trimEnd', 'trimStart', 'toNumber'],
      summaryHints: ['redos', 'regular expression'],
      reason: 'Regular Expression Denial of Service (ReDoS) in string trimming helpers',
    },
  ],
  ejs: [
    {
      symbols: ['render', 'renderFile', 'compile'],
      summaryHints: ['template', 'injection', 'rce', 'pollut', 'xss'],
      reason: 'Server-side template injection / arbitrary code execution via ejs rendering APIs',
    },
  ],
  jsonwebtoken: [
    {
      symbols: ['verify', 'decode'],
      summaryHints: ['algorithm', 'key', 'signature', 'type', 'restriction'],
      reason: 'JWT signature/algorithm validation weakness in jsonwebtoken.verify()',
    },
  ],
  minimatch: [
    {
      symbols: ['minimatch', 'match', 'filter', 'makeRe', 'Minimatch'],
      summaryHints: ['redos', 'regular expression', 'backtracking'],
      reason: 'Catastrophic backtracking ReDoS during glob matching',
    },
  ],
  'serialize-javascript': [
    {
      symbols: ['serialize', 'default'],
      summaryHints: ['xss', 'cross-site', 'regex', 'arbitrary'],
      reason: 'Cross-site scripting (XSS) / unsafe RegExp serialization in serialize-javascript',
    },
  ],
  axios: [
    {
      symbols: ['get', 'post', 'put', 'delete', 'request', 'create', 'default'],
      summaryHints: ['ssrf', 'csrf', 'xsrf', 'header', 'redirect', 'dos'],
      reason: 'HTTP client request handling vulnerability in axios transport',
    },
  ],
  qs: [
    {
      symbols: ['parse'],
      summaryHints: ['prototype', 'arraylimit', 'dos'],
      reason: 'Query-string parsing memory exhaustion / prototype pollution in qs.parse()',
    },
  ],
  marked: [
    {
      symbols: ['parse', 'marked', 'lexer'],
      summaryHints: ['redos', 'xss', 'regular expression'],
      reason: 'Markdown parser ReDoS / XSS in marked()',
    },
  ],
  tar: [
    {
      symbols: ['extract', 'x', 'unpack', 'Parse'],
      summaryHints: ['arbitrary file', 'symlink', 'path traversal'],
      reason: 'Archive extraction path traversal / symlink overwrite in node-tar',
    },
  ],
  semver: [
    {
      symbols: ['valid', 'satisfies', 'coerce', 'parse', 'gt', 'lt', 'Range'],
      summaryHints: ['redos', 'regular expression'],
      reason: 'ReDoS on untrusted semver range/version input',
    },
  ],
};

export function matchSymbolRulesForVuln(
  packageName: string,
  summary: string,
  details: string
): { symbols: string[]; note: string | null } {
  const rules = VULNERABLE_SYMBOL_RULES[packageName.toLowerCase()];
  if (!rules || rules.length === 0) {
    return { symbols: [], note: null };
  }

  const corpus = `${summary} ${details}`.toLowerCase();
  const matchedSymbols = new Set<string>();
  const reasons: string[] = [];

  for (const rule of rules) {
    if (!rule.summaryHints || rule.summaryHints.some((hint) => corpus.includes(hint))) {
      for (const s of rule.symbols) matchedSymbols.add(s);
      reasons.push(rule.reason);
    }
  }

  // If no hint matched cleanly, fall back to the union of known vulnerable entrypoints for this package
  if (matchedSymbols.size === 0) {
    for (const rule of rules) {
      for (const s of rule.symbols) matchedSymbols.add(s);
    }
    return {
      symbols: Array.from(matchedSymbols),
      note: 'Package-wide vulnerable symbol candidates applied',
    };
  }

  return {
    symbols: Array.from(matchedSymbols),
    note: reasons.join('; '),
  };
}
