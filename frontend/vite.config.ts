import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import pkg from './package.json'

export default defineConfig({
  plugins: [react()],
  define: {
    // APP_VERSION is set by the image build; the package version is the
    // fallback when running from source.
    __UI_VERSION__: JSON.stringify(process.env.APP_VERSION || pkg.version),
  },
  server: {
    port: 5173,
    // In development the API runs separately; in production nginx proxies /api.
    proxy: {
      '/api': { target: process.env.VITE_API_TARGET ?? 'http://localhost:8080', changeOrigin: true },
      '/healthz': { target: process.env.VITE_API_TARGET ?? 'http://localhost:8080', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
})
