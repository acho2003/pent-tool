export default {
  env: { NEXT_PUBLIC_API_URL: 'https://api.example.test' },
  images: { dangerouslyAllowLocalIP: false },
  experimental: { serverActions: { allowedOrigins: ['app.example.test'] } },
};
