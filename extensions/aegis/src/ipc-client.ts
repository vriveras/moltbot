import { connect, type Socket } from "node:net";
import { userInfo } from "node:os";
import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";
import {
  AEGIS_PIPE_PREFIX,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_FAIL_BEHAVIOR,
  DEFAULT_READ_TIMEOUT_MS,
} from "./constants.js";

export type AegisIpcClientOptions = {
  aegisBinaryPath: string;
  failBehavior?: "allow" | "deny";
  getFailBehavior?: () => "allow" | "deny";
  connectTimeoutMs?: number;
  readTimeoutMs?: number;
};

const VALID_DECISIONS = new Set(["allow", "deny", "ask"]);
const MAX_STDOUT_BYTES = 1_048_576; // 1 MB

/** Compute the IPC pipe path matching the aegis daemon (DaemonCommand.GetPipeName()). */
export function getDaemonPipePath(): string {
  const envOverride = process.env.AEGIS_DAEMON_PIPE_PATH;
  if (envOverride) return envOverride;
  const pipeName = `${AEGIS_PIPE_PREFIX}${userInfo().username}`;
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\${pipeName}`;
  }
  // .NET NamedPipeServerStream convention on Linux/macOS
  return `/tmp/CoreFxPipe_${pipeName}`;
}

export class AegisIpcClient {
  private readonly binaryPath: string;
  private readonly failBehavior: "allow" | "deny";
  private readonly getFailBehaviorFn?: () => "allow" | "deny";
  private readonly connectTimeoutMs: number;
  private readonly readTimeoutMs: number;

  constructor(options: AegisIpcClientOptions) {
    this.binaryPath = options.aegisBinaryPath;
    this.failBehavior = options.failBehavior ?? DEFAULT_FAIL_BEHAVIOR;
    this.getFailBehaviorFn = options.getFailBehavior;
    this.connectTimeoutMs =
      options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    this.readTimeoutMs = options.readTimeoutMs ?? DEFAULT_READ_TIMEOUT_MS;
  }

  decide(payload: OpenClawActionPayload): Promise<AegisDaemonResponse> {
    return new Promise<AegisDaemonResponse>((resolve) => {
      let settled = false;
      let socket: Socket;
      let responseData = "";

      const settle = (result: AegisDaemonResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          socket.destroy();
        } catch {
          // ignore cleanup errors
        }
        resolve(result);
      };

      try {
        socket = connect({ path: getDaemonPipePath() });
      } catch {
        resolve(this.getFailResponse());
        return;
      }

      const timer = setTimeout(() => settle(this.getFailResponse()), this.readTimeoutMs);

      socket.on("connect", () => {
        try {
          socket.write(JSON.stringify(payload) + "\n");
        } catch {
          settle(this.getFailResponse());
        }
      });

      socket.on("data", (chunk: Buffer) => {
        responseData += chunk.toString();
        if (responseData.length > MAX_STDOUT_BYTES) {
          settle(this.getFailResponse());
          return;
        }
        const newlineIdx = responseData.indexOf("\n");
        if (newlineIdx !== -1) {
          const line = responseData.slice(0, newlineIdx).trim();
          try {
            settle(this.validateResponse(JSON.parse(line)));
          } catch {
            settle(this.getFailResponse());
          }
        }
      });

      socket.on("error", () => settle(this.getFailResponse()));

      socket.on("close", () => {
        if (settled) return;
        const line = responseData.trim();
        if (!line) {
          settle(this.getFailResponse());
          return;
        }
        try {
          settle(this.validateResponse(JSON.parse(line)));
        } catch {
          settle(this.getFailResponse());
        }
      });
    });
  }

  healthCheck(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      let settled = false;
      let socket: Socket;

      const settle = (result: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          socket.destroy();
        } catch {
          // ignore cleanup errors
        }
        resolve(result);
      };

      try {
        socket = connect({ path: getDaemonPipePath() });
      } catch {
        resolve(false);
        return;
      }

      const timer = setTimeout(() => settle(false), this.connectTimeoutMs);

      socket.on("connect", () => {
        // Send a ping request the daemon can handle gracefully
        try {
          socket.write('{"ping":true}\n');
        } catch { /* ignore */ }
        settle(true);
      });
      socket.on("error", () => settle(false));
    });
  }

  dispose(): void {
    // No-op: pipe connections are short-lived and self-closing.
  }

  private getFailResponse(): AegisDaemonResponse {
    const behavior = this.getFailBehaviorFn?.() ?? this.failBehavior;
    return behavior === "deny"
      ? {
          permissionDecision: "deny",
          permissionDecisionReason: "Aegis daemon unreachable — fail-closed",
        }
      : {
          permissionDecision: "allow",
          permissionDecisionReason: "Aegis daemon unreachable — fail-open",
        };
  }

  private validateResponse(raw: unknown): AegisDaemonResponse {
    if (typeof raw !== "object" || raw === null) {
      return this.getFailResponse();
    }
    const obj = raw as Record<string, unknown>;
    if (!VALID_DECISIONS.has(obj.permissionDecision as string)) {
      return this.getFailResponse();
    }
    if (
      obj.permissionDecisionReason !== undefined &&
      typeof obj.permissionDecisionReason !== "string"
    ) {
      return this.getFailResponse();
    }
    if (obj.cookie !== undefined && typeof obj.cookie !== "string") {
      return this.getFailResponse();
    }
    return raw as AegisDaemonResponse;
  }
}
