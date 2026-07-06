import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Static marketing site build → outputs plain HTML/JS/CSS to dist/.
// No server runtime, so it deploys free to Cloudflare Pages / any static host.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
  },
});
