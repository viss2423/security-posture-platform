/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  async rewrites() {
    const api = process.env.API_URL || 'http://api:8000';
    return [
      { source: '/api/:path*', destination: `${api}/:path*` },
    ];
  },
};

module.exports = nextConfig;
