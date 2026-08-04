import { vi, describe, it, expect, afterAll } from 'vitest';

// Pre-mock environment
const originalExit = process.exit;
const mockExit = vi.fn() as any;
process.exit = mockExit;

const originalArgv = [...process.argv];
process.argv = ['node', 'mitigator-audit.ts', 'dirty-dir']; // Triggers execution of main() on import!

afterAll(() => {
  process.exit = originalExit;
  process.argv = originalArgv;
});

vi.mock('node:fs', () => {
  return {
    readdirSync: vi.fn((dir: string) => {
      if (dir === 'clean-dir') return ['clean.js'];
      if (dir === 'dirty-dir') {
        return ['secret.env', 'sub-dir', 'node_modules', '.git', 'dist', 'coverage'];
      }
      if (dir.endsWith('sub-dir')) {
        return ['app.ts', 'pollution.js'];
      }
      if (dir === 'warnings-dir') {
        return ['pollution.js'];
      }
      return [];
    }),
    statSync: vi.fn((path: string) => {
      const isDir = path.endsWith('sub-dir');
      return {
        isDirectory: () => isDir,
      };
    }),
    readFileSync: vi.fn((path: string) => {
      if (path.endsWith('clean.js')) {
        return 'const x = 1;\nconsole.log(x);';
      }
      if (path.endsWith('secret.env')) {
        return 'AWS_SECRET=ghp_123456789012345678901234567890123456';
      }
      if (path.endsWith('app.ts')) {
        return 'const app = express();\nfs.readFileSync(req.query.file);';
      }
      if (path.endsWith('pollution.js')) {
        return 'const parsed = JSON.parse(str);';
      }
      return '';
    }),
  };
});

// Import after pre-mocking
import { runAudit, main } from './mitigator-audit.js';

describe('CLI Security Audit Tool', () => {
  it('should find zero issues in clean directories', () => {
    const results = runAudit('clean-dir');
    expect(results).toHaveLength(0);
  });

  it('should identify high and medium severity vulnerabilities including subdirectories', () => {
    const results = runAudit('dirty-dir');
    expect(results.length).toBeGreaterThan(0);

    const allVulns = results.flatMap((r) => r.vulnerabilities);

    const secrets = allVulns.filter((v) => v.type === 'Hardcoded Secret');
    expect(secrets).toHaveLength(1);
    expect(secrets[0].severity).toBe('HIGH');

    const traversals = allVulns.filter((v) => v.type === 'Potential Path Traversal');
    expect(traversals).toHaveLength(1);
    expect(traversals[0].severity).toBe('HIGH');

    const pollutions = allVulns.filter((v) => v.type === 'Prototype Pollution Risk');
    expect(pollutions).toHaveLength(1);
    expect(pollutions[0].severity).toBe('MEDIUM');

    const headers = allVulns.filter((v) => v.type === 'Missing Security Headers');
    expect(headers).toHaveLength(1);
    expect(headers[0].severity).toBe('MEDIUM');
  });

  it('should run main and handle various outputs', () => {
    // 1. Test clean main run
    process.argv = ['node', 'mitigator-audit.ts', 'clean-dir'];
    mockExit.mockClear();
    main();
    expect(mockExit).toHaveBeenCalledWith(0);

    // 2. Test dirty main run (with HIGH severity)
    process.argv = ['node', 'mitigator-audit.ts', 'dirty-dir'];
    mockExit.mockClear();
    main();
    expect(mockExit).toHaveBeenCalledWith(1);

    // 3. Test warnings main run (only MEDIUM severity)
    process.argv = ['node', 'mitigator-audit.ts', 'warnings-dir'];
    mockExit.mockClear();
    main();
    expect(mockExit).toHaveBeenCalledWith(0);
  });
});
