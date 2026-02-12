/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // API routes in app/api/[...path]/route.ts handle proxying to backend
};

module.exports = nextConfig;
