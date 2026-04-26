import type { AegisPluginConfig } from "./config.js";
import { redactArgs, compileValuePatterns } from "./redaction.js";
import {
  DEFAULT_REDACT_KEY_PATTERNS,
  DEFAULT_REDACT_VALUE_PATTERNS,
  DEFAULT_APPROVAL_TIMEOUT_MS,
  DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
} from "./constants.js";

/**
 * Mirrors the `requireApproval` shape from OpenClaw's PluginHookBeforeToolCallResult.
 * Defined locally because `openclaw/plugin-sdk` does not re-export hook-types.
 */
export type ApprovalRequest = {
  title: string;
  description: string;
  severity?: "info" | "warning" | "critical";
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
};

/** Compatible with OpenClaw's PluginApprovalResolution string union. */
export type ApprovalResolution =
  | "allow-once"
  | "allow-always"
  | "deny"
  | "timeout"
  | "cancelled";

export function buildApprovalRequest(
  toolName: string,
  toolArgs: Record<string, unknown>,
  reason: string,
  config: AegisPluginConfig,
): ApprovalRequest {
  const keyPatterns = config.redactKeyPatterns ?? DEFAULT_REDACT_KEY_PATTERNS;
  const rawValuePatterns = config.redactValuePatterns ?? DEFAULT_REDACT_VALUE_PATTERNS;
  const valuePatterns = compileValuePatterns(rawValuePatterns);
  const redacted = redactArgs(toolArgs, keyPatterns, valuePatterns);

  return {
    title: `Aegis: Approval required for ${toolName}`,
    description: [
      `Policy reason: ${reason}`,
      `Tool: ${toolName}`,
      `Args: ${JSON.stringify(redacted)}`,
    ].join("\n"),
    severity: config.approvalSeverity ?? "warning",
    timeoutMs: config.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
    timeoutBehavior: config.approvalTimeoutBehavior ?? DEFAULT_APPROVAL_TIMEOUT_BEHAVIOR,
  };
}

export function handleApprovalResolution(
  resolution: ApprovalResolution | string,
  preIssuedCookie: string | undefined,
): { proceed: boolean; cookie?: string } {
  switch (resolution) {
    case "allow-once":
    case "allow-always":
      return { proceed: true, cookie: preIssuedCookie };
    case "deny":
    case "timeout":
    case "cancelled":
      return { proceed: false };
    default:
      return { proceed: false };
  }
}
