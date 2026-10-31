// Synthetic source-analysis positive controls. No real credentials.
module.exports = {
  env: { AUTH_SECRET: process.env.AUTH_SECRET },
  images: { dangerouslyAllowLocalIP: true },
  experimental: { serverActions: { allowedOrigins: ['**'] } },
};
