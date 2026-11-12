import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 개발 서버: /data, /api, /healthz 는 실행 중인 FastAPI(web)로 넘깁니다.
// 다른 주소면 KCM_API=http://host:port npm run dev
const api = process.env.KCM_API || "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
  server: {
    port: 5173,
    proxy: { "/data": api, "/api": api, "/healthz": api },
  },
});
