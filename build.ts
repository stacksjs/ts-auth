/* eslint-disable regexp/no-unused-capturing-group */
import { dts } from 'bun-plugin-dtsx'

// eslint-disable-next-line ts/no-top-level-await
await Bun.build({
  entrypoints: ['src/index.ts'],
  outdir: './dist',
  target: 'node',
  // Keep config/logging as runtime deps — bundling clarity/bunfig pulls in
  // top-level await + noisy "No config found" console.log on every import.
  external: ['bunfig', '@stacksjs/clarity', 'ts-rate-limiter'],
  plugins: [dts()],
})
