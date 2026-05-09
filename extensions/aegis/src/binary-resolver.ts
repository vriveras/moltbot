import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Resolves the bundled Aegis binary shipped in the OpenClaw `bin/` directory.
 * Returns the absolute path if found, or `null` so callers can fall back to PATH.
 */
export function resolveBundledAegisBinary(): string | null {
  const candidates = [
    path.join(process.cwd(), "bin", "aegis.exe"),
    path.join(process.cwd(), "bin", "aegis"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}
