import { fileURLToPath } from 'node:url';
const nextConfig = {
  outputFileTracingRoot: fileURLToPath(new URL('.', import.meta.url)),
  experimental: { cpus: 1 },
  distDir: process.env.LAB_VARIANT === 'vulnerable' ? '.next-vulnerable' : '.next-patched',
  productionBrowserSourceMaps: process.env.LAB_VARIANT === 'vulnerable',
  poweredByHeader: false,
};
export default nextConfig;
