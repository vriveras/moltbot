export type OpenClawActionPayload = {
  runtime: "openclaw";
  cwd: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  agentId?: string;
  sessionId?: string;
  runId?: string;
  toolCallId?: string;
  timestamp: string;
};
