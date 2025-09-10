import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: './src/renderer',
  build: {
    outDir: '../../public',
    emptyOutDir: false,
    rollupOptions: {
      input: './src/renderer/index.jsx',
      output: {
        entryFileNames: 'renderer.js',
      },
    },
  },
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src/renderer'),
    },
  },
});
