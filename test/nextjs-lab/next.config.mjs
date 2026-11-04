import { fileURLToPath } from 'node:url';
const nextConfig = {
  basePath: process.env.NEXT_PUBLIC_LAB_BASE_PATH || '',
  outputFileTracingRoot: fileURLToPath(new URL('.', import.meta.url)),
  experimental: { cpus: 1 },
  distDir: process.env.LAB_VARIANT === 'vulnerable' ? '.next-vulnerable' : '.next-patched',
  productionBrowserSourceMaps: process.env.LAB_VARIANT === 'vulnerable',
  poweredByHeader: false,
};
export default nextConfig;
