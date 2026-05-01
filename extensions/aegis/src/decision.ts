export type AegisDaemonResponse = {
  permissionDecision: "allow" | "deny" | "ask";
  permissionDecisionReason?: string;
  cookie?: string;
  envelope?: {
    mode?: string;
    sandboxProfile?: string;
    timeoutSeconds?: number;
    networkEnabled?: boolean;
    allowLocalNetwork?: boolean;
    deniedPaths?: string[];
    readonlyPaths?: string[];
    readwritePaths?: string[];
  };
};
