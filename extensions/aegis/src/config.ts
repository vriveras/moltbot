import { resolve as pathResolve } from "node:path";

import {
  DEFAULT_APPROVAL_TIMEOUT_MS,
  DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
  DEFAULT_APPROVAL_SEVERITY,
  DEFAULT_FAIL_BEHAVIOR,
} from "./constants.js";

export type AegisPluginConfig = {
  enabled?: boolean;
  aegisBinaryPath?: string;
  policyPath?: string;
  auditLogPath?: string;
  failBehavior?: "allow" | "deny";
  approvalTimeoutMs?: number;
  approvalTimeoutBehavior?: "allow" | "deny";
  approvalSeverity?: "info" | "warning" | "critical";
  /** @deprecated Use `redactKeyPatterns` and `redactValuePatterns` instead. */
  redactPatterns?: string[];
  redactKeyPatterns?: string[];
  redactValuePatterns?: string[];
};

export const DEFAULT_CONFIG: AegisPluginConfig = {
  enabled: true,
  failBehavior: DEFAULT_FAIL_BEHAVIOR,
  approvalTimeoutMs: DEFAULT_APPROVAL_TIMEOUT_MS,
  approvalTimeoutBehavior: DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
  approvalSeverity: DEFAULT_APPROVAL_SEVERITY,
  redactPatterns: undefined,
  redactKeyPatterns: undefined,
  redactValuePatterns: undefined,
};

const SHELL_METACHARACTERS = /[;|&$`<>()]/;

export function resolveConfig(raw: unknown): AegisPluginConfig {
  if (raw == null || typeof raw !== "object") {
    return { ...DEFAULT_CONFIG };
  }
  const input = raw as Record<string, unknown>;

  // --- aegisBinaryPath validation (H5) ---
  let aegisBinaryPath: string | undefined;
  if (typeof input.aegisBinaryPath === "string") {
    const trimmed = input.aegisBinaryPath.trim();
    if (trimmed.length === 0) {
      console.warn("[aegis] aegisBinaryPath is empty; ignoring");
    } else if (SHELL_METACHARACTERS.test(trimmed)) {
      console.warn("[aegis] aegisBinaryPath contains shell metacharacters; ignoring");
    } else {
      aegisBinaryPath = trimmed;
    }
  }

  // --- auditLogPath validation (H4) ---
  let auditLogPath: string | undefined;
  if (typeof input.auditLogPath === "string") {
    if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(input.auditLogPath)) {
      console.warn("[aegis] auditLogPath contains '..' segments; ignoring");
    } else {
      auditLogPath = pathResolve(input.auditLogPath);
    }
  }

  // --- redact patterns (C3) ---
  const legacyRedactPatterns = Array.isArray(input.redactPatterns)
    ? input.redactPatterns.filter((p): p is string => typeof p === "string")
    : undefined;

  const explicitKeyPatterns = Array.isArray(input.redactKeyPatterns)
    ? input.redactKeyPatterns.filter((p): p is string => typeof p === "string")
    : undefined;

  const redactKeyPatterns =
    explicitKeyPatterns ?? (legacyRedactPatterns != null ? legacyRedactPatterns : undefined);

  const redactValuePatterns = Array.isArray(input.redactValuePatterns)
    ? input.redactValuePatterns.filter((p): p is string => typeof p === "string")
    : undefined;

  return {
    enabled:
      typeof input.enabled === "boolean" ? input.enabled : DEFAULT_CONFIG.enabled,
    aegisBinaryPath,
    policyPath:
      typeof input.policyPath === "string" ? input.policyPath : undefined,
    auditLogPath,
    failBehavior:
      input.failBehavior === "allow" || input.failBehavior === "deny"
        ? input.failBehavior
        : DEFAULT_CONFIG.failBehavior,
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
    redactPatterns: legacyRedactPatterns ?? DEFAULT_CONFIG.redactPatterns,
    redactKeyPatterns,
    redactValuePatterns,
  };
}
