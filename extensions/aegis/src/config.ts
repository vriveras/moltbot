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
