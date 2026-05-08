/**
 * fix-isolation-acls.mjs
 *
 * When pnpm installs packages it creates hardlinks from node_modules/ into the
 * pnpm content-addressable store (%LOCALAPPDATA%\pnpm\store).  The hardlinked
 * files inherit the store's NTFS security descriptor, which only grants access
 * to the user who ran `pnpm install` (typically SYSTEM + Administrators + the
 * developer account).
 *
 * Inside a Windows IsolationSession the agent runs as a synthetic user (e.g.
 * "virivera-IEB-3a00") that is a member of BUILTIN\Users but is NOT the
 * installing user.  Without an explicit ACL grant the agent gets EPERM errors
 * when Node tries to load any package whose files live in the store.
 *
 * This script grants Read+Execute (RX) to BUILTIN\Users on every file in the
 * pnpm store so that IsolationSession agents can load hardlinked packages.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

if (process.platform !== "win32") {
  console.log("[fix-isolation-acls] Skipping — not running on Windows.");
  process.exit(0);
}

const localAppData = process.env.LOCALAPPDATA;
if (!localAppData) {
  console.log("[fix-isolation-acls] Skipping — %LOCALAPPDATA% is not set.");
  process.exit(0);
}

const storePath = path.join(localAppData, "pnpm", "store");
if (!existsSync(storePath)) {
  console.log(
    `[fix-isolation-acls] Skipping — pnpm store not found at "${storePath}".`,
  );
  process.exit(0);
}

console.log(
  `[fix-isolation-acls] Fixing pnpm store ACLs for IsolationSession...`,
);
console.log(
  `[fix-isolation-acls] Granting BUILTIN\\Users:(OI)(CI)(RX) on "${storePath}"`,
);

const result = spawnSync(
  "icacls",
  [storePath, "/grant", "BUILTIN\\Users:(OI)(CI)(RX)", "/T", "/C", "/Q"],
  { stdio: ["ignore", "pipe", "pipe"], encoding: "utf-8", timeout: 600_000 },
);

if (result.status !== 0) {
  const stderr = (result.stderr || "").trim();
  console.warn(
    `[fix-isolation-acls] Warning: icacls exited with code ${result.status}.`,
  );
  if (stderr) {
    console.warn(`[fix-isolation-acls] ${stderr}`);
  }
  // Don't fail the install — this is a best-effort fix.
  process.exit(0);
}

// icacls prints "Successfully processed N files; Failed processing M files"
const output = (result.stdout || "").trim();
const match = output.match(
  /Successfully processed (\d+) files?(?:; Failed processing (\d+) files?)?/i,
);
if (match) {
  const succeeded = match[1];
  const failed = match[2] || "0";
  console.log(
    `[fix-isolation-acls] Done — ${succeeded} files processed, ${failed} failures.`,
  );
} else {
  console.log(`[fix-isolation-acls] Done.`);
  if (output) {
    console.log(`[fix-isolation-acls] ${output}`);
  }
}
