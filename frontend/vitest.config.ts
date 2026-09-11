import { defineConfig, mergeConfig } from 'vitest/config'
import viteConfig from './vite.config'

// Kept apart from vite.config.ts so the production build never loads the test
// runner. The merge keeps the `@` alias, so a test imports the same paths the
// application does.
export default mergeConfig(viteConfig, defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
  },
}))
