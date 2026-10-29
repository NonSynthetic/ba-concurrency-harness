// tick_cron.ts — invoke the exported scheduled task handler against the live
// node-runtime SQLite DB. `src/index.ts`'s `scheduled` export calls
// runTaskCron(db, env, nowIso) for the task half of the tick; this script runs
// that same function on the same DB file the API server holds open (WAL).
//
// Place at: packages/api/tick_cron.ts
// Usage:
//   tsx tick_cron.ts              — one tick
//   tsx tick_cron.ts <intervalMs> <durationMs> — tick every interval for duration
import { initDatabase } from './src/db/index.js';
import { SQLiteAdapter } from './src/db/sqlite-adapter.js';
import { runTaskCron } from './src/cron/tasks.js';

const dbPath = process.env['DATABASE_PATH'] || './data/registry.db';
const db = initDatabase(dbPath);
const adapter = new SQLiteAdapter(db);
const env = { ...process.env } as Record<string, unknown>;
const intervalMs = parseInt(process.argv[2] || '0', 10);
const durationMs = parseInt(process.argv[3] || '0', 10);

async function tick(): Promise<void> {
  const summary = await runTaskCron(adapter, env, new Date().toISOString());
  console.log('[tick]', JSON.stringify(summary));
}

if (intervalMs > 0 && durationMs > 0) {
  const iv = setInterval(() => { void tick(); }, intervalMs);
  setTimeout(() => { clearInterval(iv); process.exit(0); }, durationMs);
} else {
  await tick();
}
