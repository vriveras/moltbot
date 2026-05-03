import { spawn, type ChildProcess } from "node:child_process";
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
  private readonly activeChildren = new Set<ChildProcess>();

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
      let child: ChildProcess;
      let settled = false;
      let stdout = "";

      const settle = (result: AegisDaemonResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.cleanup(child);
        resolve(result);
      };

      try {
        child = spawn(this.binaryPath, ["decide", "--openclaw"], {
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch {
        settled = true;
        resolve(this.getFailResponse());
        return;
      }

      this.activeChildren.add(child);

      const timer = setTimeout(() => {
        settle(this.getFailResponse());
      }, this.readTimeoutMs);

      child.stdout!.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
        if (stdout.length > MAX_STDOUT_BYTES) {
          settle(this.getFailResponse());
          return;
        }
        const newlineIdx = stdout.indexOf("\n");
        if (newlineIdx !== -1) {
          const line = stdout.slice(0, newlineIdx).trim();
          try {
            settle(this.validateResponse(JSON.parse(line)));
          } catch {
            settle(this.getFailResponse());
          }
        }
      });

      child.on("error", () => {
        settle(this.getFailResponse());
      });

      child.on("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          settle(this.getFailResponse());
          return;
        }
        const line = stdout.trim();
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

      try {
        child.stdin!.write(JSON.stringify(payload) + "\n");
        child.stdin!.end();
      } catch {
        settle(this.getFailResponse());
      }
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

      socket.on("connect", () => settle(true));
      socket.on("error", () => settle(false));
    });
  }

  dispose(): void {
    for (const child of this.activeChildren) {
      this.cleanup(child);
    }
    this.activeChildren.clear();
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

  private cleanup(child: ChildProcess): void {
    try {
      this.activeChildren.delete(child);
      if (!child.killed) {
        child.kill();
      }
    } catch {
      // ignore cleanup errors
    }
  }
}
