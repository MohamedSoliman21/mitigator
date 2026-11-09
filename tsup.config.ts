import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/bin/mitigator-audit.ts',
    'src/auth/index.ts',
    'src/crypto/index.ts',
    'src/fs/index.ts',
    'src/headers/index.ts',
    'src/http/index.ts',
    'src/rate-limit/index.ts',
    'src/safe-json/index.ts',
    'src/safe-merge/index.ts',
    'src/sanitize/index.ts',
    'src/utils/index.ts',
    'src/utils/presets.ts',
    'src/utils/telemetry.ts',
    'src/validate/index.ts',
  ],
  format: ['cjs', 'esm'],
  dts: {
    compilerOptions: {
      ignoreDeprecations: '6.0',
    },
  },
  clean: true,
  shims: true,
  sourcemap: true,
  minify: false,
});
