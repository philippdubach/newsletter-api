import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // These are Node tests with mocked bindings and fetch, not workerd tests.
    // Use the installed adapter instead of the unavailable miniflare environment.
    environment: 'node',
  },
});
