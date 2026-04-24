import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";

export class AegisAuditEmitter {
  emitRequested(_payload: OpenClawActionPayload): void {
    throw new Error("Not implemented");
  }

  emitDecided(_payload: OpenClawActionPayload, _decision: AegisDaemonResponse): void {
    throw new Error("Not implemented");
  }

  emitStarted(_payload: OpenClawActionPayload): void {
    throw new Error("Not implemented");
  }

  emitCompleted(
    _payload: OpenClawActionPayload,
    _result: { error?: string; durationMs?: number },
  ): void {
    throw new Error("Not implemented");
  }

  dispose(): void {
    throw new Error("Not implemented");
  }
}
