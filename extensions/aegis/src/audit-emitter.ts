import { appendFile } from "node:fs";
import { join } from "node:path";
import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";
import type { AegisPluginConfig } from "./config.js";

type AegisAuditEvent = {
  eventType: string;
  timestamp: string;
  sessionId: string;
  runtime: "openclaw";
  action: {
    kind: string;
    name: string;
    args: Record<string, unknown>;
  };
  decision?: {
    decision: string;
    reason?: string;
    policyHash?: string;
    ruleName?: string;
  };
  result?: {
    exitCode?: number;
    success?: boolean;
    durationMs?: number;
  };
  context?: {
    cwd: string;
    traceId?: string;
  };
};

const DEFAULT_AUDIT_LOG_PATH = join(".aegis", "openclaw-events.jsonl");

export class AegisAuditEmitter {
  private readonly logPath: string;
  private readonly redactPatterns: RegExp[];

  constructor(
    config: Pick<AegisPluginConfig, "auditLogPath" | "redactPatterns">,
  ) {
    this.logPath = config.auditLogPath ?? DEFAULT_AUDIT_LOG_PATH;
    this.redactPatterns = (config.redactPatterns ?? []).map(
      (p) => new RegExp(p, "g"),
    );
  }

  emitRequested(payload: OpenClawActionPayload): void {
    const event = this.buildBaseEvent("aegis.action.requested", payload);
    event.context = { cwd: process.cwd(), traceId: payload.runId };
    this.write(event);
  }

  emitDecided(
    payload: OpenClawActionPayload,
    decision: AegisDaemonResponse,
  ): void {
    const event = this.buildBaseEvent("aegis.action.decided", payload);
    event.decision = {
      decision: decision.action,
      reason: decision.reason,
      ruleName: decision.policyId,
    };
    this.write(event);
  }

  emitStarted(payload: OpenClawActionPayload): void {
    const event = this.buildBaseEvent("aegis.action.started", payload);
    event.context = { cwd: process.cwd(), traceId: payload.runId };
    this.write(event);
  }

  emitCompleted(
    payload: OpenClawActionPayload,
    result: { error?: string; durationMs?: number },
  ): void {
    const event = this.buildBaseEvent("aegis.action.completed", payload);
    event.result = {
      success: result.error == null,
      durationMs: result.durationMs,
    };
    this.write(event);
  }

  dispose(): void {
    // No buffered writes to flush — appendFile callbacks complete naturally.
  }

  private buildBaseEvent(
    eventType: string,
    payload: OpenClawActionPayload,
  ): AegisAuditEvent {
    return {
      eventType,
      timestamp: new Date().toISOString(),
      sessionId: payload.sessionId ?? payload.sessionKey ?? "",
      runtime: "openclaw",
      action: {
        kind: "tool_call",
        name: payload.toolName,
        args: this.redactArgs(payload.params),
      },
    };
  }

  private redactArgs(
    args: Record<string, unknown>,
  ): Record<string, unknown> {
    if (this.redactPatterns.length === 0) return args;
    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string") {
        let matched = false;
        for (const pattern of this.redactPatterns) {
          pattern.lastIndex = 0;
          if (pattern.test(value)) {
            matched = true;
            break;
          }
        }
        redacted[key] = matched ? "[REDACTED]" : value;
      } else {
        redacted[key] = value;
      }
    }
    return redacted;
  }

  private write(event: AegisAuditEvent): void {
    try {
      const line = JSON.stringify(event) + "\n";
      appendFile(this.logPath, line, (err) => {
        if (err) {
          console.warn(`[aegis] Failed to write audit event: ${err.message}`);
        }
      });
    } catch (err) {
      console.warn(`[aegis] Failed to serialize audit event: ${err}`);
    }
  }
}
