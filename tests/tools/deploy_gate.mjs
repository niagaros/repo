// Deployment gate (issue #279): P0 checks that must hold before a build is allowed to ship.
// Runs inside the Amplify build (frontend/amplify.yml preBuild) and in CI. Exit code 1 blocks the deploy.
// No dependencies — Node 18+ (global fetch). Set GATE_API_BASE to point it elsewhere (used to prove it fails).
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const API = process.env.GATE_API_BASE || 'https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default';
const here = dirname(fileURLToPath(import.meta.url));
const publicDir = join(here, '..', '..', 'frontend', 'public');
const results = [];

async function check(id, name, fn) {
  try {
    const detail = await fn();
    results.push({ id, name, ok: true, detail });
  } catch (e) {
    results.push({ id, name, ok: false, detail: String(e.message || e) });
  }
}

const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const get = (path, headers = {}) => fetch(`${API}/${path}`, { headers, signal: AbortSignal.timeout(20000) });

await check('E2E-AUTH-001', 'dashboard rejects a request with no credentials', async () => {
  const r = await get('get-dashboard-data');
  if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
  return '401';
});
await check('E2E-AUTH-001', 'dashboard rejects a forged unsigned (alg=none) JWT', async () => {
  const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ email: 'admin@niagaros.com' })}.`;
  const r = await get('get-dashboard-data', { Authorization: `Bearer ${forged}` });
  if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
  return '401';
});
for (const path of ['notifications', 'tprm', 'questionnaires', 'audit-management', 'trust-center', 'custom-frameworks', 'ai-agent']) {
  await check('E2E-PERM-001', `${path}: anonymous callers cannot read an account's data`, async () => {
    const r = await get(`${path}?cloud_account_id=00000000-0000-4000-8000-000000000000`);
    if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
    return '401';
  });
}
await check('E2E-PERM-001', 'monthly report preview requires a session (it returns a full account report)', async () => {
  const r = await fetch(`${API}/monthly-report-preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cloud_account_id: '00000000-0000-4000-8000-000000000000' }), signal: AbortSignal.timeout(20000) });
  if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
  return '401';
});
await check('E2E-ONB-002', 'onboarding requires a signed-in user', async () => {
  const r = await fetch(`${API}/onboard`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: AbortSignal.timeout(20000) });
  if (r.status !== 401) throw new Error(`expected 401, got ${r.status}`);
  return '401';
});
await check('E2E-PLAT-001', 'database is available according to the independent status endpoint', async () => {
  const r = await get('status');
  if (r.status !== 200) throw new Error(`status endpoint answered ${r.status}`);
  const d = await r.json();
  if (d.database?.status !== 'operational') throw new Error(`database is ${d.database?.status}`);
  return `database operational, overall ${d.overall_status}`;
});
await check('E2E-SEC-002', 'no page puts an escaped value inside an inline handler string (XSS)', async () => {
  const bad = /on[a-z]+="[^"]*'\$\{[^}]*\b(esc|escape|escapeHtml|escHtml)\(/;
  const hits = [];
  for (const f of readdirSync(publicDir).filter(n => n.endsWith('.html'))) {
    readFileSync(join(publicDir, f), 'utf8').split('\n').forEach((line, i) => { if (bad.test(line)) hits.push(`${f}:${i + 1}`); });
  }
  if (hits.length) throw new Error(`vulnerable pattern in ${hits.join(', ')}`);
  return 'no offenders';
});

for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}  — ${r.detail}`);
const failed = results.filter(r => !r.ok);
if (failed.length) {
  console.error(`\nDEPLOYMENT BLOCKED: ${failed.length} P0 check(s) failed.`);
  process.exit(1);
}
console.log(`\nGate open: ${results.length}/${results.length} P0 checks passed.`);
