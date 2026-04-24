import type { AegisDaemonResponse } from "./decision.js";
import type { OpenClawActionPayload } from "./action-request.js";

export function buildApprovalRequest(
  _payload: OpenClawActionPayload,
  _decision: AegisDaemonResponse,
): {
  title: string;
  description: string;
  severity?: "info" | "warning" | "critical";
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
} {
  throw new Error("Not implemented");
}

export function handleApprovalResolution(
  _resolution: string,
  _payload: OpenClawActionPayload,
): void {
  throw new Error("Not implemented");
}
