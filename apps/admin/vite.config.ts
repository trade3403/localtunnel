import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
const port = Number(process.env.LOCALTUNNEL_API_PORT || '1431')
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid local API port')
const proxy = { '/api/v1': { target: 'http://127.0.0.1:' + port, changeOrigin: false } }
export default defineConfig({
  plugins: [vue()],
  server: { host: '127.0.0.1', port: 1430, strictPort: true, proxy, cors: false },
  preview: { host: '127.0.0.1', port: 1430, strictPort: true, proxy, cors: false },
})
