import { spawn, type ChildProcess } from "node:child_process";
import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";
import {
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_READ_TIMEOUT_MS,
} from "./constants.js";

export type AegisIpcClientOptions = {
  aegisBinaryPath: string;
  connectTimeoutMs?: number;
  readTimeoutMs?: number;
};

const FAIL_CLOSED: AegisDaemonResponse = {
  action: "deny",
  reason: "Aegis daemon unreachable — fail-closed",
};

export class AegisIpcClient {
  private readonly binaryPath: string;
  private readonly connectTimeoutMs: number;
  private readonly readTimeoutMs: number;
  private readonly activeChildren = new Set<ChildProcess>();

  constructor(options: AegisIpcClientOptions) {
    this.binaryPath = options.aegisBinaryPath;
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
        resolve(FAIL_CLOSED);
        return;
      }

      this.activeChildren.add(child);

      const timer = setTimeout(() => {
        settle(FAIL_CLOSED);
      }, this.readTimeoutMs);

      child.stdout!.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
        const newlineIdx = stdout.indexOf("\n");
        if (newlineIdx !== -1) {
          const line = stdout.slice(0, newlineIdx).trim();
          try {
            settle(JSON.parse(line) as AegisDaemonResponse);
          } catch {
            settle(FAIL_CLOSED);
          }
        }
      });

      child.on("error", () => {
        settle(FAIL_CLOSED);
      });

      child.on("close", (code) => {
        if (settled) return;
        if (code !== 0) {
          settle(FAIL_CLOSED);
          return;
        }
        const line = stdout.trim();
        if (!line) {
          settle(FAIL_CLOSED);
          return;
        }
        try {
          settle(JSON.parse(line) as AegisDaemonResponse);
        } catch {
          settle(FAIL_CLOSED);
        }
      });

      try {
        child.stdin!.write(JSON.stringify(payload) + "\n");
        child.stdin!.end();
      } catch {
        settle(FAIL_CLOSED);
      }
    });
  }

  healthCheck(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      let child: ChildProcess;
      let settled = false;

      const settle = (result: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          if (!child.killed) child.kill();
        } catch {
          // ignore cleanup errors
        }
        resolve(result);
      };

      try {
        child = spawn(this.binaryPath, ["--version"], {
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch {
        resolve(false);
        return;
      }

      const timer = setTimeout(() => settle(false), this.connectTimeoutMs);

      child.on("error", () => settle(false));
      child.on("close", (code) => settle(code === 0));
    });
  }

  dispose(): void {
    for (const child of this.activeChildren) {
      this.cleanup(child);
    }
    this.activeChildren.clear();
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
