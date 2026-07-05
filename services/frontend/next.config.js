/** @type {import('next').NextConfig} */
const nextConfig = {
  // Docker builds need standalone output; the @cloudflare/next-on-pages build must not have it.
  // The Dockerfile sets NEXT_OUTPUT_STANDALONE=1; all other builds get the default output.
  output: process.env.NEXT_OUTPUT_STANDALONE === '1' ? 'standalone' : undefined,
  turbopack: {
    root: __dirname,
  },
  // API routes in app/api/[...path]/route.ts proxy to backend.
};

module.exports = nextConfig;
