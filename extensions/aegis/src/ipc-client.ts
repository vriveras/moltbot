import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";

export class AegisIpcClient {
  decide(_payload: OpenClawActionPayload): Promise<AegisDaemonResponse> {
    throw new Error("Not implemented");
  }

  healthCheck(): Promise<boolean> {
    throw new Error("Not implemented");
  }

  dispose(): void {
    throw new Error("Not implemented");
  }
}
