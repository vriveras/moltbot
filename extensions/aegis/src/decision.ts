export type AegisDaemonResponse = {
  action: "allow" | "deny" | "require_approval";
  reason?: string;
  modifiedParams?: Record<string, unknown>;
  approvalTitle?: string;
  approvalDescription?: string;
  approvalSeverity?: "info" | "warning" | "critical";
  policyId?: string;
  executionMetadata?: Record<string, unknown>;
};
