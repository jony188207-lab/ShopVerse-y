/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'X-Robots-Tag', value: 'noindex, nofollow' },
];
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Lint runs as its own step (`npm run lint`); a style rule must never block a production deploy. Type errors still fail the build.
  eslint: { ignoreDuringBuilds: true },
  async headers() { return [{ source: '/:path*', headers: securityHeaders }]; },
};
export default nextConfig;
