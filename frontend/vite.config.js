import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import AutoImport from 'unplugin-auto-import/vite';
import Components from 'unplugin-vue-components/vite';
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers';
import { fileURLToPath, URL } from 'node:url';
export default defineConfig({
    plugins: [
        vue(),
        AutoImport({
            imports: ['vue', 'vue-router', 'pinia', 'vue-i18n'],
            resolvers: [ElementPlusResolver()],
            dts: 'src/auto-imports.d.ts',
            vueTemplate: true,
        }),
        Components({
            resolvers: [ElementPlusResolver()],
            dts: 'src/components.d.ts',
        }),
    ],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
        },
    },
    server: {
        proxy: {
            '/api': {
                target: 'https://10.174.254.136:8443',
                changeOrigin: true,
                secure: false,
            },
        },
    },
    build: {
        target: 'es2015',
        cssCodeSplit: true,
        rollupOptions: {
            output: {
                manualChunks: {
                    'vendor-vue': ['vue', 'vue-router', 'pinia'],
                    'vendor-elplus': ['element-plus'],
                    'vendor-i18n': ['vue-i18n'],
                },
            },
        },
        chunkSizeWarningLimit: 600,
    },
});
