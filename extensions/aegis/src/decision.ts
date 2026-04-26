export type AegisDaemonResponse = {
  permissionDecision: "allow" | "deny" | "ask";
  permissionDecisionReason?: string;
  cookie?: string;
};
