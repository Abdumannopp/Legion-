// Fails unless every job the release gate waits for succeeded.
// GitHub passes the `needs` context as JSON in NEEDS. "skipped" and
// "cancelled" count as failures: a release must never ride on a check that
// did not actually run.
const needs = JSON.parse(process.env.NEEDS ?? "{}");
const entries = Object.entries(needs);
if (!entries.length) {
  console.log("::error::release gate received no job results");
  process.exit(1);
}
const bad = entries.filter(([, v]) => v?.result !== "success");
for (const [job, v] of entries) console.log(`${v?.result === "success" ? "✓" : "✗"} ${job}: ${v?.result}`);
for (const [job, v] of bad) console.log(`::error::${job} = ${v?.result}`);
process.exit(bad.length ? 1 : 0);
