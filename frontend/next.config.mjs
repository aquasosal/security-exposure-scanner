import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Output standalone for Vercel deployment
  output: 'standalone',

  // Environment variables for API calls
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  },
};

export default nextConfig;
