import * as os from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";

/** Well-known search paths for wxc-exec on Windows. */
const WXC_SEARCH_PATHS = [
  path.join(process.cwd(), "bin", "wxc-exec.exe"),
  "wxc-exec.exe",
  path.join(os.homedir(), ".mxc", "wxc-exec.exe"),
];

/** Well-known search paths for lxc-exec on Linux. */
const LXC_SEARCH_PATHS = [
  path.join(process.cwd(), "bin", "lxc-exec"),
  "lxc-exec",
  "/usr/local/bin/lxc-exec",
  path.join(os.homedir(), ".mxc", "lxc-exec"),
];

function findOnPath(binary: string): string | null {
  const pathEnv = process.env.PATH ?? "";
  const sep = os.platform() === "win32" ? ";" : ":";
  for (const dir of pathEnv.split(sep)) {
    const candidate = path.join(dir, binary);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function findBinary(searchPaths: string[]): string | null {
  for (const p of searchPaths) {
    // If it's a bare name, search PATH
    if (!path.isAbsolute(p) && !p.includes(path.sep)) {
      const found = findOnPath(p);
      if (found) return found;
    } else if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

/**
 * Resolves the MXC executor binary path.
 * @param configOverride Optional user-configured path override.
 * @returns Absolute path to the binary.
 * @throws If the binary cannot be found.
 */
export function resolveMxcBinaryPath(configOverride?: string): string {
  if (configOverride) {
    if (!fs.existsSync(configOverride)) {
      throw new Error(
        `MXC binary not found at configured path: ${configOverride}`,
      );
    }
    return configOverride;
  }

  const platform = os.platform();
  const searchPaths = platform === "linux" ? LXC_SEARCH_PATHS : WXC_SEARCH_PATHS;
  const found = findBinary(searchPaths);

  if (!found) {
    const binary = platform === "linux" ? "lxc-exec" : "wxc-exec.exe";
    throw new Error(
      `MXC binary "${binary}" not found. Build the MXC workspace or set mxcBinaryPath in config.`,
    );
  }
  return found;
}
