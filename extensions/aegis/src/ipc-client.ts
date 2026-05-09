import { spawn, type ChildProcess } from "node:child_process";
import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";
import {
  DEFAULT_FAIL_BEHAVIOR,
  DEFAULT_READ_TIMEOUT_MS,
} from "./constants.js";

export type AegisIpcClientOptions = {
  aegisBinaryPath: string;
  failBehavior?: "allow" | "deny";
  getFailBehavior?: () => "allow" | "deny";
  readTimeoutMs?: number;
};

const VALID_DECISIONS = new Set(["allow", "deny", "ask"]);
const MAX_STDOUT_BYTES = 1_048_576; // 1 MB

export class AegisIpcClient {
  private readonly binaryPath: string;
  private readonly failBehavior: "allow" | "deny";
  private readonly getFailBehaviorFn?: () => "allow" | "deny";
  private readonly readTimeoutMs: number;

  constructor(options: AegisIpcClientOptions) {
    this.binaryPath = options.aegisBinaryPath;
    this.failBehavior = options.failBehavior ?? DEFAULT_FAIL_BEHAVIOR;
    this.getFailBehaviorFn = options.getFailBehavior;
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
        try { child?.kill(); } catch { /* ignore */ }
        resolve(result);
      };

      try {
        child = spawn(this.binaryPath, ["decide", "--openclaw"], {
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch {
        resolve(this.getFailResponse());
        return;
      }

      const timer = setTimeout(() => settle(this.getFailResponse()), this.readTimeoutMs);

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

      child.on("error", () => settle(this.getFailResponse()));
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

  dispose(): void {
    // No-op: subprocess calls are short-lived.
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
