/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  turbopack: {
    root: `${__dirname}/../..`,
  },
  // API routes in app/api/[...path]/route.ts handle proxying to backend
};

module.exports = nextConfig;
