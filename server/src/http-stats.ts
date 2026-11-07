/**
 * In-process HTTP request statistics for /metrics: counts by status CLASS and
 * a latency histogram. Deliberately no route, tenant or path label — the
 * cardinality stays fixed and nothing about a request can reach a metric.
 */
export const LATENCY_BUCKETS_SECONDS = [0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] as const;
const CLASSES = ["1xx", "2xx", "3xx", "4xx", "5xx"] as const;

const counts: Record<string, number> = Object.fromEntries(CLASSES.map((c) => [c, 0]));
const buckets = new Array<number>(LATENCY_BUCKETS_SECONDS.length + 1).fill(0); // last = +Inf
let sum = 0;
let total = 0;

export function recordRequest(status: number, seconds: number): void {
  const cls = `${Math.min(5, Math.max(1, Math.floor(status / 100)))}xx`;
  counts[cls] = (counts[cls] ?? 0) + 1;
  total++; sum += seconds;
  let i = LATENCY_BUCKETS_SECONDS.findIndex((b) => seconds <= b);
  if (i < 0) i = LATENCY_BUCKETS_SECONDS.length;
  buckets[i]!++;
}

/** Prometheus text for the above (cumulative buckets, as the format requires). */
export function renderHttpStats(): string {
  const out = ["# HELP legion_http_requests_total HTTP responses by status class.", "# TYPE legion_http_requests_total counter"];
  for (const c of CLASSES) out.push(`legion_http_requests_total{class="${c}"} ${counts[c]}`);
  out.push("# HELP legion_http_request_duration_seconds Time to answer an HTTP request.", "# TYPE legion_http_request_duration_seconds histogram");
  let cumulative = 0;
  LATENCY_BUCKETS_SECONDS.forEach((b, i) => { cumulative += buckets[i]!; out.push(`legion_http_request_duration_seconds_bucket{le="${b}"} ${cumulative}`); });
  cumulative += buckets[LATENCY_BUCKETS_SECONDS.length]!;
  out.push(`legion_http_request_duration_seconds_bucket{le="+Inf"} ${cumulative}`, `legion_http_request_duration_seconds_sum ${Math.round(sum * 1000) / 1000}`, `legion_http_request_duration_seconds_count ${total}`);
  return out.join("\n") + "\n";
}

/** Tests only. */
export function resetHttpStats(): void {
  for (const c of CLASSES) counts[c] = 0;
  buckets.fill(0); sum = 0; total = 0;
}
