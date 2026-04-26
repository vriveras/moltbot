export type MxcConfig = {
  enabled: boolean;
  mxcBinaryPath?: string;
  aegisPublicKeyPath?: string;
  defaultContainment: "process" | "wslc" | "microvm";
  debug: boolean;
};

export function resolveConfig(raw: unknown): MxcConfig {
  if (raw == null || typeof raw !== "object") {
    return { enabled: true, defaultContainment: "process", debug: false };
  }
  const input = raw as Record<string, unknown>;
  return {
    enabled: typeof input.enabled === "boolean" ? input.enabled : true,
    mxcBinaryPath:
      typeof input.mxcBinaryPath === "string" && input.mxcBinaryPath.trim().length > 0
        ? input.mxcBinaryPath.trim()
        : undefined,
    aegisPublicKeyPath:
      typeof input.aegisPublicKeyPath === "string" && input.aegisPublicKeyPath.trim().length > 0
        ? input.aegisPublicKeyPath.trim()
        : undefined,
    defaultContainment:
      input.defaultContainment === "process" ||
      input.defaultContainment === "wslc" ||
      input.defaultContainment === "microvm"
        ? input.defaultContainment
        : "process",
    debug: input.debug === true,
  };
}
