/**
 * Scheduler service — runs cron jobs in a separate tick to avoid blocking the event loop.
 * Prevents node-cron "missed execution" warnings caused by long-running fetch cycles.
 */
const cron = require('node-cron');

const jobs = [];

/**
 * Register a cron job that runs asynchronously without blocking the scheduler.
 * @param {string} expression - Cron expression
 * @param {Function} task - Async function to run
 * @param {object} [opts]
 * @param {string} [opts.name] - Job name for logging
 */
function schedule(expression, task, opts = {}) {
  const name = opts.name || `job-${jobs.length}`;
  const job = cron.schedule(expression, async () => {
    process.nextTick(async () => {
      try {
        await task();
      } catch (err) {
        console.error(`[Scheduler] ${name} failed:`, err.message);
      }
    });
  });
  jobs.push({ name, job });
  console.log(`[Scheduler] Registered: ${name} (${expression})`);
}

/**
 * Gracefully stop all scheduled jobs.
 */
async function stopAll() {
  for (const { name, job } of jobs) {
    job.stop();
    console.log(`[Scheduler] Stopped: ${name}`);
  }
}

module.exports = { schedule, stopAll };
