import type { NextConfig } from "next";

// The console always calls same-origin /api/* — Next proxies to the platform
// server, so the browser never needs CORS. In the dev cage, dev.ps1 supplies
// BLASTCONTAIN_API_URL (the WSL gateway = the Windows host; discovered at
// launch because host.containers.internal only reaches the podman VM).
const API_URL = process.env.BLASTCONTAIN_API_URL ?? "http://host.containers.internal:8080";

const nextConfig: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_URL}/:path*` }];
  },
};

export default nextConfig;
