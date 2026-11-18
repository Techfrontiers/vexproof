import cors from 'cors';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from '../core/scanner.js';
import type { SignedVexBundle } from '../core/types.js';
import { verifyVexBundle } from '../core/vex-compiler.js';

const PORT = Number.parseInt(process.env.VEXPROOF_PORT ?? '4311', 10);
const WORKSPACE_ROOT = process.cwd();

export function createVexproofApp() {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '5mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'vexproof-api',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/samples', (_req, res) => {
    const examplesDir = path.join(WORKSPACE_ROOT, 'examples');
    const samples: Array<{ id: string; name: string; path: string; description: string }> = [];
    if (fs.existsSync(examplesDir)) {
      for (const entry of fs.readdirSync(examplesDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const abs = path.join(examplesDir, entry.name);
        const pkgFile = path.join(abs, 'package.json');
        let desc = 'Local repository sample';
        if (fs.existsSync(pkgFile)) {
          try {
            const parsed = JSON.parse(fs.readFileSync(pkgFile, 'utf8')) as { description?: string };
            if (parsed.description) desc = parsed.description;
          } catch {
            // Keep default description
          }
        }
        samples.push({
          id: entry.name,
          name: entry.name,
          path: abs,
          description: desc,
        });
      }
    }
    res.json({
      workspaceRoot: WORKSPACE_ROOT,
      samples,
    });
  });

  app.post('/api/scan', async (req, res) => {
    try {
      const targetPathOrUrl = String(req.body?.targetPathOrUrl ?? '').trim();
      const offlineOnly = Boolean(req.body?.offlineOnly);
      if (!targetPathOrUrl) {
        res.status(400).json({ error: 'targetPathOrUrl is required' });
        return;
      }

      const resolvedTarget =
        targetPathOrUrl.startsWith('https://')
          ? targetPathOrUrl
          : path.isAbsolute(targetPathOrUrl)
            ? targetPathOrUrl
            : path.resolve(WORKSPACE_ROOT, targetPathOrUrl);

      const report = await scanProject(resolvedTarget, {
        offlineOnly,
        cacheBaseDir: WORKSPACE_ROOT,
      });

      res.json(report);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Scan execution failed',
      });
    }
  });

  app.post('/api/verify', (req, res) => {
    try {
      const bundle = req.body?.bundle as SignedVexBundle | undefined;
      if (!bundle || !bundle.document) {
        res.status(400).json({ error: 'SignedVexBundle payload is required' });
        return;
      }
      const overridePub =
        typeof req.body?.publicKeyPem === 'string' && req.body.publicKeyPem.trim()
          ? req.body.publicKeyPem
          : undefined;

      const verdict = verifyVexBundle(bundle, overridePub);
      res.json(verdict);
    } catch (err) {
      res.status(400).json({
        valid: false,
        reason: err instanceof Error ? err.message : 'Invalid JSON payload',
      });
    }
  });

  app.get('/api/source-snippet', (req, res) => {
    const repoPath = String(req.query.repoPath ?? '').trim();
    const file = String(req.query.file ?? '').trim();
    const focusLine = Number.parseInt(String(req.query.line ?? '1'), 10) || 1;

    if (!repoPath || !file || repoPath.startsWith('https://')) {
      res.status(400).json({ error: 'Local repoPath and relative file are required' });
      return;
    }

    const base = path.isAbsolute(repoPath) ? repoPath : path.resolve(WORKSPACE_ROOT, repoPath);
    const full = path.resolve(base, file);
    if (!full.startsWith(base) || !fs.existsSync(full)) {
      res.status(404).json({ error: 'Source file not found inside repository boundary' });
      return;
    }

    const lines = fs.readFileSync(full, 'utf8').split(/\r?\n/);
    const start = Math.max(1, focusLine - 6);
    const end = Math.min(lines.length, focusLine + 6);
    const snippet = lines.slice(start - 1, end).map((content, idx) => ({
      lineNumber: start + idx,
      content,
      isFocus: start + idx === focusLine,
    }));

    res.json({ file, focusLine, snippet });
  });

  const distUi = path.join(WORKSPACE_ROOT, 'dist-ui');
  if (fs.existsSync(distUi)) {
    app.use(express.static(distUi));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distUi, 'index.html'));
    });
  }

  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]).endsWith('server/index.ts') ||
    process.argv[1] && path.resolve(process.argv[1]).endsWith('server\\index.ts') ||
    process.argv[1] && path.resolve(process.argv[1]).endsWith('server\\index.js') ||
    process.argv[1] && path.resolve(process.argv[1]).endsWith('server/index.js')) {
  const app = createVexproofApp();
  app.listen(PORT, () => {
    console.log(`VEXProof Forensic API listening on http://localhost:${PORT}`);
  });
}
