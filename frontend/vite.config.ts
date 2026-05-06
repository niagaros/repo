import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // SPA mode: serve index.html for all non-file routes (enables React Router BrowserRouter)
  appType: "spa",
});
