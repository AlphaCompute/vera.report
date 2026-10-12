/** Trusted proxy hops, counted from the right. Deployed CloudFront -> ALB ->
 * Express uses 2; ingress must reject direct or shorter paths before enabling it.
 * Local/single-load-balancer deployments retain the default of 1. */
export function apiTrustProxyHops(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.API_TRUST_PROXY_HOPS;
  if (raw === undefined || raw === '') return 1;
  if (!/^[0-9]$/.test(raw)) throw new Error('API_TRUST_PROXY_HOPS must be an integer from 0 to 9');
  return Number(raw);
}
