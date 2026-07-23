import { performance } from "node:perf_hooks";

const base = "https://oqyrbdvehvqdcpglaojo.supabase.co";
const concurrency = boundedInt(process.env.LOAD_CONCURRENCY, 10, 1, 100);
const durationSeconds = boundedInt(process.env.LOAD_DURATION_SECONDS, 30, 5, 300);
const anonKey = process.env.SUPABASE_ANON_KEY || "";

const targets = [
  {
    name: "shield-metadata",
    url: `${base}/storage/v1/object/public/app-releases/shieldproxy/latest.json`,
    validate: async (response) => {
      const body = await response.json();
      return body.packageName === "com.privacyshield.proxy" && body.versionCode > 0;
    },
  },
  {
    name: "blackbox-metadata",
    url: `${base}/storage/v1/object/public/app-releases/blackbox/latest.json`,
    validate: async (response) => {
      const body = await response.json();
      return body.packageName === "top.niunaijun.blackbox" && body.versionCode > 0;
    },
  },
];

if (anonKey) {
  const authHeaders = { apikey: anonKey, Authorization: `Bearer ${anonKey}` };
  targets.push(
    {
      name: "auth-health",
      url: `${base}/auth/v1/health`,
      headers: { apikey: anonKey },
      validate: async (response) => (await response.json()).name === "GoTrue",
    },
    {
      name: "backup-rls",
      url: `${base}/rest/v1/app_backups?select=user_id&limit=1`,
      headers: authHeaders,
      validate: async (response) => (await response.text()).trim() === "[]",
    },
    {
      name: "crash-report-rls",
      url: `${base}/rest/v1/crash_reports?select=id&limit=1`,
      headers: authHeaders,
      validate: async (response) => (await response.text()).trim() === "[]",
    },
  );
}

const deadline = performance.now() + durationSeconds * 1000;
const samples = new Map(targets.map((target) => [
  target.name,
  { latencies: [], ok: 0, failed: 0, statuses: new Map() },
]));
let nextTarget = 0;

async function worker() {
  while (performance.now() < deadline) {
    const target = targets[nextTarget++ % targets.length];
    const stats = samples.get(target.name);
    const started = performance.now();
    try {
      const response = await fetch(target.url, {
        headers: target.headers,
        cache: "no-store",
        signal: AbortSignal.timeout(10_000),
      });
      const valid = response.ok && await target.validate(response);
      stats.statuses.set(response.status, (stats.statuses.get(response.status) || 0) + 1);
      if (valid) stats.ok++;
      else stats.failed++;
    } catch {
      stats.failed++;
    } finally {
      stats.latencies.push(performance.now() - started);
    }
  }
}

const startedAt = performance.now();
await Promise.all(Array.from({ length: concurrency }, worker));
const elapsedSeconds = (performance.now() - startedAt) / 1000;
let totalOk = 0;
let totalFailed = 0;

console.log(`profile concurrency=${concurrency} duration=${durationSeconds}s actual=${elapsedSeconds.toFixed(1)}s`);
for (const [name, stats] of samples) {
  stats.latencies.sort((a, b) => a - b);
  totalOk += stats.ok;
  totalFailed += stats.failed;
  console.log(JSON.stringify({
    target: name,
    requests: stats.ok + stats.failed,
    ok: stats.ok,
    failed: stats.failed,
    p50Ms: percentile(stats.latencies, 0.50),
    p95Ms: percentile(stats.latencies, 0.95),
    p99Ms: percentile(stats.latencies, 0.99),
    statuses: Object.fromEntries(stats.statuses),
  }));
}

const total = totalOk + totalFailed;
const failureRate = total === 0 ? 1 : totalFailed / total;
console.log(JSON.stringify({
  total,
  ok: totalOk,
  failed: totalFailed,
  failureRate,
  requestsPerSecond: Number((total / elapsedSeconds).toFixed(2)),
}));
if (failureRate > 0.01) process.exitCode = 1;

function percentile(values, fraction) {
  if (values.length === 0) return null;
  return Number(values[Math.min(values.length - 1, Math.floor(values.length * fraction))].toFixed(1));
}

function boundedInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}
