import { appendFile } from "node:fs";
import { join, resolve as pathResolve } from "node:path";
import type { OpenClawActionPayload } from "./action-request.js";
import type { AegisDaemonResponse } from "./decision.js";
import { redactArgs, compileValuePatterns } from "./redaction.js";
import { DEFAULT_REDACT_KEY_PATTERNS, DEFAULT_REDACT_VALUE_PATTERNS } from "./constants.js";

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
  private readonly redactValuePatterns: RegExp[];
  private readonly redactKeyPatterns: string[];

  constructor(
    config: {
      auditLogPath?: string;
      redactKeyPatterns?: string[];
      redactValuePatterns?: string[];
    },
  ) {
    const rawPath = config.auditLogPath ?? DEFAULT_AUDIT_LOG_PATH;
    this.logPath = pathResolve(rawPath);

    const rawValuePatterns = config.redactValuePatterns ?? DEFAULT_REDACT_VALUE_PATTERNS;
    this.redactValuePatterns = compileValuePatterns(rawValuePatterns);
    this.redactKeyPatterns = config.redactKeyPatterns ?? DEFAULT_REDACT_KEY_PATTERNS;
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
      decision: decision.permissionDecision,
      reason: decision.permissionDecisionReason,
    };
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

  emitApprovalResolved(
    toolCallId: string,
    toolName: string,
    resolution: string,
    sessionId?: string,
  ): void {
    const event: AegisAuditEvent = {
      eventType: "aegis.approval.resolved",
      timestamp: new Date().toISOString(),
      sessionId: sessionId ?? "",
      runtime: "openclaw",
      action: {
        kind: "tool_call",
        name: toolName,
        args: {},
      },
      decision: {
        decision: resolution,
      },
      context: {
        cwd: process.cwd(),
        traceId: toolCallId,
      },
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
      sessionId: payload.sessionId ?? "",
      runtime: "openclaw",
      action: {
        kind: "tool_call",
        name: payload.toolName,
        args: this.redactArgs(payload.toolArgs),
      },
    };
  }

  private redactArgs(
    args: Record<string, unknown>,
  ): Record<string, unknown> {
    return redactArgs(
      args,
      this.redactKeyPatterns,
      this.redactValuePatterns,
    ) as Record<string, unknown>;
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
