import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import type {
  AstAnalysisSummary,
  CallGraphEdge,
  CallGraphNode,
  CallSite,
  DynamicHazard,
} from './types.js';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'dist-ui',
  'build',
  'coverage',
  '.vexproof-cache',
  '.vexproof-out',
  '.next',
]);

const JS_TS_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

function walkSourceFiles(rootDir: string): { jsTsFiles: string[]; pyFiles: string[] } {
  const jsTsFiles: string[] = [];
  const pyFiles: string[] = [];

  const visit = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (JS_TS_EXTS.has(ext) && !entry.name.endsWith('.d.ts')) {
          jsTsFiles.push(fullPath);
        } else if (ext === '.py') {
          pyFiles.push(fullPath);
        }
      }
    }
  };

  visit(rootDir);
  return { jsTsFiles, pyFiles };
}

function getPackageRootName(specifier: string): string | null {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('node:')) {
    return null;
  }
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  return specifier.split('/')[0];
}

interface FileAnalysis {
  relPath: string;
  sourceFile: ts.SourceFile;
  /** Local symbol aliases imported from external packages: localIdentifier -> { packageName, exportName } */
  externalAliases: Map<string, { packageName: string; exportName: string }>;
  /** Local imports from relative project files: localIdentifier -> resolvedRelPath */
  localImportFiles: Map<string, string>;
  /** Functions defined in this file */
  definedFunctions: Map<string, { id: string; name: string; line: number; isEntrypoint: boolean }>;
  /** Intra-file or exported caller -> callees */
  functionCalls: Array<{ callerId: string; calleeName: string; line: number }>;
  /** Direct external package calls: callerId -> CallSite */
  externalCallSites: Array<{ callerId: string; packageName: string; site: CallSite }>;
  hazards: DynamicHazard[];
}

function resolveRelativeTsFile(fromFile: string, specifier: string, allRelPaths: Set<string>, rootDir: string): string | null {
  if (!specifier.startsWith('.')) return null;
  const fromDir = path.dirname(fromFile);
  const candidateBase = path.relative(rootDir, path.resolve(fromDir, specifier)).replace(/\\/g, '/');
  const stripped = candidateBase.replace(/\.(js|mjs|cjs)$/, '');
  const trials = [
    candidateBase,
    `${stripped}.ts`,
    `${stripped}.tsx`,
    `${stripped}.js`,
    `${stripped}.mjs`,
    `${stripped}/index.ts`,
    `${stripped}/index.js`,
  ];
  for (const t of trials) {
    if (allRelPaths.has(t)) return t;
  }
  return null;
}

function getLineCol(sourceFile: ts.SourceFile, pos: number): { line: number; column: number } {
  const lc = sourceFile.getLineAndCharacterOfPosition(pos);
  return { line: lc.line + 1, column: lc.character + 1 };
}

function extractLineSnippet(sourceFile: ts.SourceFile, line: number): string {
  const lines = sourceFile.text.split(/\r?\n/);
  return (lines[line - 1] ?? '').trim().slice(0, 140);
}

function hasExportModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return Boolean(mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword));
}

function isRouteRegistrationCall(node: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(node.expression)) return false;
  const method = node.expression.name.text.toLowerCase();
  return ['get', 'post', 'put', 'patch', 'delete', 'use', 'all', 'listen', 'command', 'action'].includes(method);
}

function analyzeSingleTsFile(
  absPath: string,
  rootDir: string,
  allRelPaths: Set<string>,
  entrypointFileHints: Set<string>
): FileAnalysis {
  const relPath = path.relative(rootDir, absPath).replace(/\\/g, '/');
  const text = fs.readFileSync(absPath, 'utf8');
  const sourceFile = ts.createSourceFile(absPath, text, ts.ScriptTarget.Latest, true);

  const externalAliases = new Map<string, { packageName: string; exportName: string }>();
  const localImportFiles = new Map<string, string>();
  const definedFunctions = new Map<string, { id: string; name: string; line: number; isEntrypoint: boolean }>();
  const functionCalls: Array<{ callerId: string; calleeName: string; line: number }> = [];
  const externalCallSites: Array<{ callerId: string; packageName: string; site: CallSite }> = [];
  const hazards: DynamicHazard[] = [];

  const fileModuleId = `${relPath}::<module>`;
  const isModuleEntry =
    entrypointFileHints.has(relPath) ||
    /(^|\/)(index|main|server|app|cli|handler|route)\.(ts|tsx|js|jsx|mjs)$/.test(relPath);

  definedFunctions.set(fileModuleId, {
    id: fileModuleId,
    name: `${relPath}::<module>`,
    line: 1,
    isEntrypoint: isModuleEntry,
  });

  const fnStack: string[] = [fileModuleId];
  const currentCaller = () => fnStack[fnStack.length - 1];

  const registerExternalImport = (localName: string, specifier: string, exportName: string) => {
    const pkgRoot = getPackageRootName(specifier);
    if (pkgRoot) {
      // Handle subpath imports like `lodash/template` -> symbol `template`
      const subpath = specifier.startsWith('@')
        ? specifier.split('/').slice(2).join('/')
        : specifier.split('/').slice(1).join('/');
      const effectiveExport = subpath ? subpath.replace(/\.js$/, '') : exportName;
      externalAliases.set(localName, { packageName: pkgRoot, exportName: effectiveExport });
      return;
    }
    const localRel = resolveRelativeTsFile(absPath, specifier, allRelPaths, rootDir);
    if (localRel) {
      localImportFiles.set(localName, localRel);
    }
  };

  const visit = (node: ts.Node) => {
    // 1. ES module imports
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text;
      const clause = node.importClause;
      if (clause?.name) {
        registerExternalImport(clause.name.text, spec, 'default');
      }
      if (clause?.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          registerExternalImport(clause.namedBindings.name.text, spec, '*');
        } else if (ts.isNamedImports(clause.namedBindings)) {
          for (const elem of clause.namedBindings.elements) {
            const orig = elem.propertyName?.text ?? elem.name.text;
            registerExternalImport(elem.name.text, spec, orig);
          }
        }
      }
    }

    // 2. CommonJS require() variable declarations
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === 'require'
    ) {
      const arg0 = node.initializer.arguments[0];
      if (arg0 && ts.isStringLiteral(arg0)) {
        const spec = arg0.text;
        if (ts.isIdentifier(node.name)) {
          registerExternalImport(node.name.text, spec, '*');
        } else if (ts.isObjectBindingPattern(node.name)) {
          for (const elem of node.name.elements) {
            if (ts.isIdentifier(elem.name)) {
              const orig = elem.propertyName && ts.isIdentifier(elem.propertyName)
                ? elem.propertyName.text
                : elem.name.text;
              registerExternalImport(elem.name.text, spec, orig);
            }
          }
        }
      } else {
        const { line, column } = getLineCol(sourceFile, node.getStart(sourceFile));
        hazards.push({
          file: relPath,
          line,
          column,
          kind: 'dynamic-require',
          snippet: extractLineSnippet(sourceFile, line),
        });
      }
    }

    // 3. Function declarations, arrow functions assigned to variables, methods
    let pushedFn = false;
    if (ts.isFunctionDeclaration(node) && node.name) {
      const fnName = node.name.text;
      const { line } = getLineCol(sourceFile, node.getStart(sourceFile));
      const id = `${relPath}::${fnName}`;
      definedFunctions.set(id, {
        id,
        name: fnName,
        line,
        isEntrypoint: hasExportModifier(node) || isModuleEntry,
      });
      fnStack.push(id);
      pushedFn = true;
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      const fnName = node.name.text;
      const { line } = getLineCol(sourceFile, node.getStart(sourceFile));
      const id = `${relPath}::${fnName}`;
      const isExported =
        node.parent?.parent && ts.isVariableStatement(node.parent.parent)
          ? hasExportModifier(node.parent.parent)
          : false;
      definedFunctions.set(id, {
        id,
        name: fnName,
        line,
        isEntrypoint: isExported || isModuleEntry,
      });
      fnStack.push(id);
      pushedFn = true;
    }

    // 4. Route callback handlers e.g. app.get('/route', (req, res) => ...)
    if (ts.isCallExpression(node) && isRouteRegistrationCall(node)) {
      const handlerId = `${relPath}::route@${getLineCol(sourceFile, node.getStart(sourceFile)).line}`;
      const { line } = getLineCol(sourceFile, node.getStart(sourceFile));
      definedFunctions.set(handlerId, {
        id: handlerId,
        name: `routeHandler@${line}`,
        line,
        isEntrypoint: true,
      });
      functionCalls.push({ callerId: fileModuleId, calleeName: handlerId, line });

      for (const arg of node.arguments) {
        if (ts.isIdentifier(arg)) {
          functionCalls.push({ callerId: handlerId, calleeName: arg.text, line });
        } else if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
          fnStack.push(handlerId);
          ts.forEachChild(arg, visit);
          fnStack.pop();
        }
      }
      if (pushedFn) fnStack.pop();
      return;
    }

    // 5. Call Expressions -> check dynamic hazards, external package calls, and local calls
    if (ts.isCallExpression(node)) {
      const { line, column } = getLineCol(sourceFile, node.getStart(sourceFile));
      const caller = currentCaller();

      if (ts.isIdentifier(node.expression)) {
        const callee = node.expression.text;
        if (callee === 'eval') {
          hazards.push({ file: relPath, line, column, kind: 'eval', snippet: extractLineSnippet(sourceFile, line) });
        } else if (callee === 'require' && (!node.arguments[0] || !ts.isStringLiteral(node.arguments[0]))) {
          hazards.push({
            file: relPath,
            line,
            column,
            kind: 'dynamic-require',
            snippet: extractLineSnippet(sourceFile, line),
          });
        } else {
          const ext = externalAliases.get(callee);
          if (ext) {
            externalCallSites.push({
              callerId: caller,
              packageName: ext.packageName,
              site: {
                file: relPath,
                line,
                column,
                callerFunction: caller,
                importedAs: callee,
                memberCalled: ext.exportName === '*' ? callee : ext.exportName,
                snippet: extractLineSnippet(sourceFile, line),
              },
            });
          } else {
            functionCalls.push({ callerId: caller, calleeName: callee, line });
          }
        }
      } else if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg0 = node.arguments[0];
        if (!arg0 || !ts.isStringLiteral(arg0)) {
          hazards.push({
            file: relPath,
            line,
            column,
            kind: 'dynamic-import',
            snippet: extractLineSnippet(sourceFile, line),
          });
        }
      } else if (ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const prop = node.expression.name.text;
        if (ts.isIdentifier(obj)) {
          if (obj.text === 'Reflect') {
            hazards.push({
              file: relPath,
              line,
              column,
              kind: 'reflect-call',
              snippet: extractLineSnippet(sourceFile, line),
            });
          }
          const ext = externalAliases.get(obj.text);
          if (ext) {
            externalCallSites.push({
              callerId: caller,
              packageName: ext.packageName,
              site: {
                file: relPath,
                line,
                column,
                callerFunction: caller,
                importedAs: obj.text,
                memberCalled: prop,
                snippet: extractLineSnippet(sourceFile, line),
              },
            });
          } else if (localImportFiles.has(obj.text)) {
            functionCalls.push({ callerId: caller, calleeName: `${localImportFiles.get(obj.text)}::${prop}`, line });
          } else {
            functionCalls.push({ callerId: caller, calleeName: prop, line });
          }
        }
      }
    }

    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
      const { line, column } = getLineCol(sourceFile, node.getStart(sourceFile));
      hazards.push({
        file: relPath,
        line,
        column,
        kind: 'new-function',
        snippet: extractLineSnippet(sourceFile, line),
      });
    }

    ts.forEachChild(node, visit);
    if (pushedFn) fnStack.pop();
  };

  visit(sourceFile);

  return {
    relPath,
    sourceFile,
    externalAliases,
    localImportFiles,
    definedFunctions,
    functionCalls,
    externalCallSites,
    hazards,
  };
}

function analyzePythonFileImports(
  absPath: string,
  rootDir: string,
  packagesImported: Record<string, CallSite[]>
): void {
  const relPath = path.relative(rootDir, absPath).replace(/\\/g, '/');
  const lines = fs.readFileSync(absPath, 'utf8').split(/\r?\n/);
  lines.forEach((rawLine, idx) => {
    const trimmed = rawLine.trim();
    const m = trimmed.match(/^(?:from\s+([A-Za-z0-9_.\-]+)\s+import\s+([A-Za-z0-9_.*,\s]+)|import\s+([A-Za-z0-9_.\-]+))/);
    if (!m) return;
    const pkg = (m[1] || m[3]).split('.')[0].toLowerCase();
    const member = m[2] ? m[2].split(',')[0].trim() : null;
    if (!packagesImported[pkg]) packagesImported[pkg] = [];
    packagesImported[pkg].push({
      file: relPath,
      line: idx + 1,
      column: 1,
      callerFunction: `${relPath}::<module>`,
      importedAs: pkg,
      memberCalled: member,
      snippet: trimmed.slice(0, 140),
    });
  });
}

export interface AnalyzedProjectGraph {
  summary: AstAnalysisSummary;
  /** Package name -> shortest reachable call chain strings from any entrypoint */
  reachableChainsByPkg: Map<string, Map<string, string[]>>;
  /** All call sites per package (even inside uncalled dead functions) */
  allCallSitesByPkg: Map<string, CallSite[]>;
  /** All reachable function IDs in the project graph */
  reachableFunctionIds: Set<string>;
}

export function analyzeProjectReachability(rootDir: string): AnalyzedProjectGraph {
  const pkgJsonPath = path.join(rootDir, 'package.json');
  const entrypointFileHints = new Set<string>();
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')) as {
        main?: string;
        bin?: string | Record<string, string>;
      };
      if (pkg.main) entrypointFileHints.add(pkg.main.replace(/^\.\//, ''));
      if (typeof pkg.bin === 'string') entrypointFileHints.add(pkg.bin.replace(/^\.\//, ''));
      else if (pkg.bin && typeof pkg.bin === 'object') {
        for (const p of Object.values(pkg.bin)) entrypointFileHints.add(p.replace(/^\.\//, ''));
      }
    } catch {
      // Ignore malformed package.json
    }
  }

  const { jsTsFiles, pyFiles } = walkSourceFiles(rootDir);
  const allRelPaths = new Set(jsTsFiles.map((f) => path.relative(rootDir, f).replace(/\\/g, '/')));

  const fileAnalyses = jsTsFiles.map((abs) => analyzeSingleTsFile(abs, rootDir, allRelPaths, entrypointFileHints));

  const nodesMap = new Map<string, CallGraphNode>();
  const adj = new Map<string, string[]>();
  const edges: CallGraphEdge[] = [];
  const nameLookup = new Map<string, string[]>(); // simple function name -> full ids
  const hazards: DynamicHazard[] = [];
  const packagesImported: Record<string, CallSite[]> = {};
  const allCallSitesByPkg = new Map<string, CallSite[]>();

  for (const fa of fileAnalyses) {
    hazards.push(...fa.hazards);

    for (const [id, fn] of fa.definedFunctions) {
      nodesMap.set(id, {
        id,
        label: fn.name,
        kind: fn.isEntrypoint ? 'entrypoint' : 'function',
        file: fa.relPath,
        line: fn.line,
      });
      const shortList = nameLookup.get(fn.name) ?? [];
      shortList.push(id);
      nameLookup.set(fn.name, shortList);
    }
  }

  for (const fa of fileAnalyses) {
    for (const call of fa.functionCalls) {
      let targetIds: string[] = [];
      if (call.calleeName.includes('::')) {
        if (nodesMap.has(call.calleeName)) targetIds = [call.calleeName];
      } else {
        const sameFileId = `${fa.relPath}::${call.calleeName}`;
        if (nodesMap.has(sameFileId)) {
          targetIds = [sameFileId];
        } else if (fa.localImportFiles.has(call.calleeName)) {
          const importedFile = fa.localImportFiles.get(call.calleeName)!;
          const impId = `${importedFile}::${call.calleeName}`;
          if (nodesMap.has(impId)) targetIds = [impId];
          else if (nodesMap.has(`${importedFile}::<module>`)) targetIds = [`${importedFile}::<module>`];
        } else {
          targetIds = nameLookup.get(call.calleeName) ?? [];
        }
      }

      for (const tid of targetIds) {
        const list = adj.get(call.callerId) ?? [];
        list.push(tid);
        adj.set(call.callerId, list);
        edges.push({ from: call.callerId, to: tid, kind: 'calls' });
      }
    }

    for (const extCall of fa.externalCallSites) {
      const { callerId, packageName, site } = extCall;
      if (!packagesImported[packageName]) packagesImported[packageName] = [];
      packagesImported[packageName].push(site);

      const list = allCallSitesByPkg.get(packageName) ?? [];
      list.push(site);
      allCallSitesByPkg.set(packageName, list);

      const extNodeId = `ext:${packageName}.${site.memberCalled ?? '*'}`;
      if (!nodesMap.has(extNodeId)) {
        nodesMap.set(extNodeId, {
          id: extNodeId,
          label: `${packageName}.${site.memberCalled ?? '*'}`,
          kind: 'external-symbol',
          file: site.file,
          line: site.line,
        });
      }
      edges.push({ from: callerId, to: extNodeId, kind: 'imports' });
    }
  }

  // BFS from all entrypoints to determine which functions are actually reachable at runtime
  const reachableFunctionIds = new Set<string>();
  const parentPath = new Map<string, string[]>();
  const queue: string[] = [];

  for (const node of nodesMap.values()) {
    if (node.kind === 'entrypoint') {
      reachableFunctionIds.add(node.id);
      parentPath.set(node.id, [node.id]);
      queue.push(node.id);
    }
  }

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const neighbors = adj.get(curr) ?? [];
    for (const nxt of neighbors) {
      if (!reachableFunctionIds.has(nxt)) {
        reachableFunctionIds.add(nxt);
        parentPath.set(nxt, [...(parentPath.get(curr) ?? [curr]), nxt]);
        queue.push(nxt);
      }
    }
  }

  // Build reachable chains for external symbols
  const reachableChainsByPkg = new Map<string, Map<string, string[]>>();
  for (const [pkg, sites] of allCallSitesByPkg) {
    const symbolMap = new Map<string, string[]>();
    for (const site of sites) {
      if (!reachableFunctionIds.has(site.callerFunction)) {
        continue; // Dead/unreached function call site!
      }
      const sym = site.memberCalled ?? '*';
      if (!symbolMap.has(sym)) {
        const prefix = parentPath.get(site.callerFunction) ?? [site.callerFunction];
        symbolMap.set(sym, [
          ...prefix,
          `${pkg}.${sym} (${site.file}:${site.line})`,
        ]);
      }
    }
    if (symbolMap.size > 0) {
      reachableChainsByPkg.set(pkg, symbolMap);
    }
  }

  for (const pyAbs of pyFiles) {
    analyzePythonFileImports(pyAbs, rootDir, packagesImported);
  }

  const entrypointsFound = Array.from(nodesMap.values()).filter((n) => n.kind === 'entrypoint').length;

  return {
    summary: {
      filesScanned: jsTsFiles.length + pyFiles.length,
      entrypointsFound,
      functionsMapped: Array.from(nodesMap.values()).filter((n) => n.kind !== 'external-symbol').length,
      edgesMapped: edges.length,
      dynamicHazards: hazards,
      packagesImported,
      nodes: Array.from(nodesMap.values()),
      edges,
    },
    reachableChainsByPkg,
    allCallSitesByPkg,
    reachableFunctionIds,
  };
}
