import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  server: { proxy: { '^/a/[^/]+/api': 'http://127.0.0.1:18080' } },
  build: { sourcemap: false, target: 'es2020' },
});
