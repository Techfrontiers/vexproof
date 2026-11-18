import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const errors = [];

const requiredPaths = [
  '.kiro/steering/product.md',
  '.kiro/steering/tech.md',
  '.kiro/steering/structure.md',
  '.kiro/specs/vexproof-core/requirements.md',
  '.kiro/specs/vexproof-core/design.md',
  '.kiro/specs/vexproof-core/tasks.md',
  '.kiro/hooks/test-on-save.json',
  '.kiro/hooks/kiroween-guard.json',
  '.kiro/agents/vex-auditor.json',
  '.kiro/settings/mcp.json',
  'LICENSE',
  'README.md',
];

for (const rel of requiredPaths) {
  if (!fs.existsSync(path.join(root, rel))) {
    errors.push(`Missing required Kiroween artifact: ${rel}`);
  }
}

const gitignorePath = path.join(root, '.gitignore');
if (fs.existsSync(gitignorePath)) {
  const lines = fs
    .readFileSync(gitignorePath, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  for (const line of lines) {
    if (line === '.kiro' || line === '.kiro/' || line === '/.kiro' || line === '/.kiro/') {
      errors.push(`.gitignore MUST NOT ignore .kiro directory (found "${line}")`);
    }
  }
} else {
  errors.push('Missing .gitignore');
}

if (errors.length > 0) {
  console.error('❌ Kiroween 2026 Compliance Check FAILED:');
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
}

console.log('✅ Kiroween 2026 Compliance Check PASSED: .kiro specs/hooks/agents/mcp present and tracked.');
