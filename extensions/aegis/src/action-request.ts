export type OpenClawActionPayload = {
  toolName: string;
  params: Record<string, unknown>;
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolCallId?: string;
  timestamp: string;
};
