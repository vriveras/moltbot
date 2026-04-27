import type { AegisEnforcementConfig } from "../config/types.node-host.js";
import { resolveExecutableFromPathEnv } from "../infra/executable-path.js";

export type ResolvedAegisEnforcementConfig = {
  aegisBinaryPath: string;
  mxcBinaryPath: string;
  daemonPipePath?: string;
  enabled: boolean;
};

const AEGIS_BIN = "aegis";

function defaultMxcBinName(): string | null {
  switch (process.platform) {
    case "win32": return "wxc-exec";
    case "linux": return "lxc-exec";
    default: return null; // No MXC binary on macOS/other
  }
}

function resolveFromEnvOrPath(
  explicit: string | undefined,
  envVar: string,
  binName: string,
  pathEnv: string,
): string | undefined {
  if (explicit) return explicit;
  const fromEnv = process.env[envVar];
  if (fromEnv) return fromEnv;
  return resolveExecutableFromPathEnv(binName, pathEnv) ?? undefined;
}

/**
 * Resolve Aegis enforcement config from the node-host config section and environment.
 * Returns null when enforcement is not configured or explicitly disabled.
 */
export function resolveAegisEnforcementConfig(
  configSection: AegisEnforcementConfig | undefined,
  pathEnv?: string,
): ResolvedAegisEnforcementConfig | null {
  if (configSection?.enabled === false) return null;

  const effectivePath = pathEnv ?? process.env.PATH ?? "";

  const aegisBinary = resolveFromEnvOrPath(
    configSection?.aegisBinaryPath,
    "AEGIS_BINARY_PATH",
    AEGIS_BIN,
    effectivePath,
  );
  if (!aegisBinary) return null;

  const mxcBinName = defaultMxcBinName();
  if (!mxcBinName) return null; // Platform not supported for MXC

  const mxcBinary = resolveFromEnvOrPath(
    configSection?.mxcBinaryPath,
    "MXC_BINARY_PATH",
    mxcBinName,
    effectivePath,
  );
  if (!mxcBinary) return null;

  return {
    aegisBinaryPath: aegisBinary,
    mxcBinaryPath: mxcBinary,
    daemonPipePath: configSection?.daemonPipePath,
    enabled: true,
  };
}
