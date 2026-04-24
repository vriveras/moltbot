import {
  DEFAULT_APPROVAL_TIMEOUT_MS,
  DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
  DEFAULT_APPROVAL_SEVERITY,
  DEFAULT_HEALTH_CHECK_INTERVAL_MS,
} from "./constants.js";

export type AegisPluginConfig = {
  enabled?: boolean;
  aegisBinaryPath?: string;
  policyPath?: string;
  auditLogPath?: string;
  approvalTimeoutMs?: number;
  approvalTimeoutBehavior?: "allow" | "deny";
  approvalSeverity?: "info" | "warning" | "critical";
  healthCheckIntervalMs?: number;
  redactPatterns?: string[];
};

export const DEFAULT_CONFIG: AegisPluginConfig = {
  enabled: true,
  approvalTimeoutMs: DEFAULT_APPROVAL_TIMEOUT_MS,
  approvalTimeoutBehavior: DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
  approvalSeverity: DEFAULT_APPROVAL_SEVERITY,
  healthCheckIntervalMs: DEFAULT_HEALTH_CHECK_INTERVAL_MS,
  redactPatterns: [],
};

export function resolveConfig(raw: unknown): AegisPluginConfig {
  if (raw == null || typeof raw !== "object") {
    return { ...DEFAULT_CONFIG };
  }
  const input = raw as Record<string, unknown>;
  return {
    enabled:
      typeof input.enabled === "boolean" ? input.enabled : DEFAULT_CONFIG.enabled,
    aegisBinaryPath:
      typeof input.aegisBinaryPath === "string"
        ? input.aegisBinaryPath
        : undefined,
    policyPath:
      typeof input.policyPath === "string" ? input.policyPath : undefined,
    auditLogPath:
      typeof input.auditLogPath === "string" ? input.auditLogPath : undefined,
    approvalTimeoutMs:
      typeof input.approvalTimeoutMs === "number"
        ? input.approvalTimeoutMs
        : DEFAULT_CONFIG.approvalTimeoutMs,
    approvalTimeoutBehavior:
      input.approvalTimeoutBehavior === "allow" ||
      input.approvalTimeoutBehavior === "deny"
        ? input.approvalTimeoutBehavior
        : DEFAULT_CONFIG.approvalTimeoutBehavior,
    approvalSeverity:
      input.approvalSeverity === "info" ||
      input.approvalSeverity === "warning" ||
      input.approvalSeverity === "critical"
        ? input.approvalSeverity
        : DEFAULT_CONFIG.approvalSeverity,
    healthCheckIntervalMs:
      typeof input.healthCheckIntervalMs === "number"
        ? input.healthCheckIntervalMs
        : DEFAULT_CONFIG.healthCheckIntervalMs,
    redactPatterns: Array.isArray(input.redactPatterns)
      ? input.redactPatterns.filter((p): p is string => typeof p === "string")
      : DEFAULT_CONFIG.redactPatterns,
  };
}
