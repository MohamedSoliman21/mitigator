#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { scanForSecrets } from '../validate/index.js';

interface AuditResult {
  filePath: string;
  vulnerabilities: {
    type: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    message: string;
    line?: number;
  }[];
}

const findFiles = (dir: string, fileList: string[] = []): string[] => {
  try {
    const files = readdirSync(dir);
    for (const file of files) {
      if (file === 'node_modules' || file === '.git' || file === 'dist' || file === 'coverage')
        continue;
      const filePath = join(dir, file);
      const stat = statSync(filePath);
      if (stat.isDirectory()) {
        findFiles(filePath, fileList);
      } else {
        const ext = extname(file);
        if (['.js', '.ts', '.json', '.env', '.yml', '.yaml'].includes(ext)) {
          fileList.push(filePath);
        }
      }
    }
  } catch {}
  return fileList;
};

const auditFile = (filePath: string): AuditResult => {
  const result: AuditResult = { filePath, vulnerabilities: [] };
  try {
    const content = readFileSync(filePath, 'utf8');
    const ext = extname(filePath);

    // 1. Plaintext Secret Scanning
    if (ext !== '.json') {
      const lines = content.split(/\r?\n/);
      lines.forEach((line, idx) => {
        if (scanForSecrets(line)) {
          result.vulnerabilities.push({
            type: 'Hardcoded Secret',
            severity: 'HIGH',
            message: `Potential plaintext API key or credential leak detected.`,
            line: idx + 1,
          });
        }
      });
    }

    // 2. Dangerous File Sync / Path Traversal
    if (ext === '.js' || ext === '.ts') {
      const traversalRegex =
        /fs\.(readFileSync|writeFileSync|readFile|writeFile)\(.*req\.(query|body|params)\./;
      if (traversalRegex.test(content)) {
        result.vulnerabilities.push({
          type: 'Potential Path Traversal',
          severity: 'HIGH',
          message:
            'Direct user input passed to a file system operation without path lock validation.',
        });
      }

      // 3. Unsafe Merging without prototype check
      if (content.includes('Object.assign(') || content.includes('JSON.parse(')) {
        if (
          !content.includes('safeMerge') &&
          !content.includes('safeJson') &&
          !content.includes('lockdownPrototypes')
        ) {
          result.vulnerabilities.push({
            type: 'Prototype Pollution Risk',
            severity: 'MEDIUM',
            message:
              'Raw JSON parsing or object assignment used without Prototype Pollution defense.',
          });
        }
      }

      // 4. Missing secure headers in standard http/express setups
      if (
        content.includes('express()') &&
        !content.includes('presets.expressMiddleware') &&
        !content.includes('helmet')
      ) {
        result.vulnerabilities.push({
          type: 'Missing Security Headers',
          severity: 'MEDIUM',
          message:
            'Express application instance created but no security middleware preset detected.',
        });
      }
    }
  } catch {}
  return result;
};

export const runAudit = (targetDir: string = '.'): AuditResult[] => {
  const files = findFiles(targetDir);
  const results: AuditResult[] = [];
  for (const file of files) {
    const res = auditFile(file);
    if (res.vulnerabilities.length > 0) {
      results.push(res);
    }
  }
  return results;
};

// Main Execution
export const main = () => {
  const args = process.argv.slice(2);
  const target = args[0] || '.';
  console.log(
    `🛡️  Mitigator Security Audit: Scanning [${target}] for vulnerabilities and configuration drifts...\n`,
  );

  const results = runAudit(target);
  let totalHigh = 0;
  let totalMedium = 0;

  if (results.length === 0) {
    console.log('✅ No security vulnerabilities or drifts found. Keep up the high standard!');
    process.exit(0);
  }

  results.forEach((res) => {
    console.log(`📂 File: ${res.filePath}`);
    res.vulnerabilities.forEach((vuln) => {
      const color = vuln.severity === 'HIGH' ? '\x1b[31m[HIGH]\x1b[0m' : '\x1b[33m[MEDIUM]\x1b[0m';
      if (vuln.severity === 'HIGH') totalHigh++;
      if (vuln.severity === 'MEDIUM') totalMedium++;
      const lineStr = vuln.line ? ` (line ${vuln.line})` : '';
      console.log(`  ${color} ${vuln.type}: ${vuln.message}${lineStr}`);
    });
    console.log('');
  });

  console.log(
    `📊 Audit Summary: Found ${totalHigh} HIGH and ${totalMedium} MEDIUM severity alerts.`,
  );
  if (totalHigh > 0) {
    console.log(
      '\x1b[31m❌ Audit Failed: Critical vulnerabilities must be resolved before merging.\x1b[0m',
    );
    process.exit(1);
  } else {
    console.log('\x1b[32m⚠️  Audit Passed with warnings.\x1b[0m');
    process.exit(0);
  }
};

// Only execute when run directly
/* v8 ignore next 11 */
if (
  (typeof require !== 'undefined' && require.main === module) ||
  (process.argv[1] &&
    (process.argv[1].endsWith('mitigator-audit') ||
      process.argv[1].endsWith('mitigator-audit.js') ||
      process.argv[1].endsWith('mitigator-audit.ts')))
) {
  main();
}
