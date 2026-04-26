import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { isAbsolute } from "node:path";

// --- Mocks ---

const appendFileMock = vi.hoisted(() => vi.fn());

vi.mock("node:fs", () => ({
  appendFile: appendFileMock,
}));

import { AegisAuditEmitter } from "../src/audit-emitter.js";

// --- Helpers ---

function makePayload(overrides?: Record<string, unknown>) {
  return {
    runtime: "openclaw" as const,
    cwd: process.cwd(),
    toolName: "bash",
    toolArgs: { command: "echo hello" } as Record<string, unknown>,
    sessionId: "session-1",
    sessionKey: "key-1",
    runId: "run-42",
    timestamp: "2025-01-15T12:00:00.000Z",
    ...overrides,
  };
}

/** Capture all lines written via the mocked appendFile. */
function captureLines(): string[] {
  const lines: string[] = [];
  appendFileMock.mockImplementation(
    (_path: string, data: string, cb: (err: Error | null) => void) => {
      lines.push(data);
      cb(null);
    },
  );
  return lines;
}

/** Parse a single captured JSONL line (trims trailing newline). */
function parseLine(line: string): Record<string, unknown> {
  return JSON.parse(line.trimEnd()) as Record<string, unknown>;
}

// --- Tests ---

describe("AegisAuditEmitter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. emitRequested schema
  test("emitRequested writes event with correct schema", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(makePayload());

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.requested");
    expect(event.runtime).toBe("openclaw");
    expect(event.sessionId).toBe("session-1");
    // timestamp is ISO 8601
    expect(typeof event.timestamp).toBe("string");
    expect(() => new Date(event.timestamp as string)).not.toThrow();
    // action fields
    const action = event.action as Record<string, unknown>;
    expect(action.kind).toBe("tool_call");
    expect(action.name).toBe("bash");
    expect(action.args).toEqual({ command: "echo hello" });
    // context
    const context = event.context as Record<string, unknown>;
    expect(context.traceId).toBe("run-42");
  });

  // 2. emitDecided schema
  test("emitDecided writes event with decision fields", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitDecided(makePayload(), {
      permissionDecision: "deny",
      permissionDecisionReason: "blocked",
    });

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.decided");
    const decision = event.decision as Record<string, unknown>;
    expect(decision.decision).toBe("deny");
    expect(decision.reason).toBe("blocked");
  });

  // 3. emitCompleted schema
  test("emitCompleted writes event with result fields", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitCompleted(makePayload(), { durationMs: 120 });

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.action.completed");
    const result = event.result as Record<string, unknown>;
    expect(result.success).toBe(true);
    expect(result.durationMs).toBe(120);
  });

  // 4. emitCompleted with error marks success false
  test("emitCompleted marks success false when error is present", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitCompleted(makePayload(), { error: "boom", durationMs: 50 });

    const event = parseLine(lines[0]!);
    const result = event.result as Record<string, unknown>;
    expect(result.success).toBe(false);
  });

  // 5. JSONL format — multiple events, each valid JSON, newline-terminated
  test("multiple events produce valid JSONL (one JSON object per line)", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(makePayload());
    emitter.emitDecided(makePayload(), { permissionDecision: "allow" });
    emitter.emitCompleted(makePayload(), { durationMs: 10 });

    expect(lines).toHaveLength(3);
    for (const line of lines) {
      // Each line ends with newline
      expect(line.endsWith("\n")).toBe(true);
      // Each line is valid JSON
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  // 6. Error handling — appendFile callback error does not propagate
  test("appendFile callback error logs warning but does not throw", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    appendFileMock.mockImplementation(
      (_path: string, _data: string, cb: (err: Error | null) => void) => {
        cb(new Error("disk full"));
      },
    );

    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    // Should not throw
    expect(() => emitter.emitRequested(makePayload())).not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("disk full"),
    );

    warnSpy.mockRestore();
  });

  // 7. Redaction — sensitive values are replaced with [REDACTED]
  test("redactValuePatterns replaces matching string arg values", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({
      auditLogPath: "test.jsonl",
      redactValuePatterns: ["sk-[a-zA-Z0-9]+", "password=\\S+"],
    });

    const payload = makePayload({
      toolArgs: {
        command: "curl -H 'Authorization: Bearer sk-abc123'",
        safe: "normal-value",
        creds: "password=s3cret",
        numeric: 42,
      },
    });

    emitter.emitRequested(payload);

    const event = parseLine(lines[0]!);
    const action = event.action as Record<string, unknown>;
    const args = action.args as Record<string, unknown>;
    expect(args.command).toBe("[REDACTED]");
    expect(args.safe).toBe("normal-value");
    expect(args.creds).toBe("[REDACTED]");
    // Non-string values pass through unchanged
    expect(args.numeric).toBe(42);
  });

  // 8. sessionId defaults to empty string when undefined
  test("uses empty string when sessionId is undefined", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitRequested(
      makePayload({ sessionId: undefined, sessionKey: "fallback-key" }),
    );

    const event = parseLine(lines[0]!);
    expect(event.sessionId).toBe("");
  });

  // 9. Oversized regex patterns are skipped
  test("skips oversized regex patterns (>500 chars)", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const lines = captureLines();
    const oversized = "a".repeat(501);
    const emitter = new AegisAuditEmitter({
      auditLogPath: "test.jsonl",
      redactValuePatterns: [oversized, "sk-[a-zA-Z0-9]+"],
    });

    const payload = makePayload({
      toolArgs: { token: "sk-abc123", safe: "ok" },
    });
    emitter.emitRequested(payload);

    // The oversized pattern was skipped with a warning
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("Skipping oversized redact pattern"),
    );
    // The valid pattern still works
    const event = parseLine(lines[0]!);
    const action = event.action as Record<string, unknown>;
    const args = action.args as Record<string, unknown>;
    expect(args.token).toBe("[REDACTED]");
    expect(args.safe).toBe("ok");

    warnSpy.mockRestore();
  });

  // 10. Default value patterns are applied when not provided
  test("uses default value patterns when redactValuePatterns not provided", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    const payload = makePayload({
      toolArgs: { auth: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", safe: "ok" },
    });
    emitter.emitRequested(payload);

    const event = parseLine(lines[0]!);
    const action = event.action as Record<string, unknown>;
    const args = action.args as Record<string, unknown>;
    expect(args.auth).toBe("[REDACTED]");
    expect(args.safe).toBe("ok");
  });

  // 11. Audit log path is resolved to absolute
  test("resolves audit log path to absolute", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "relative/path.jsonl" });

    emitter.emitRequested(makePayload());

    expect(lines).toHaveLength(1);
    // appendFile was called with an absolute path
    const writtenPath = appendFileMock.mock.calls[0]![0] as string;
    expect(isAbsolute(writtenPath)).toBe(true);
    expect(writtenPath).toContain("relative");
  });

  // 12. emitApprovalResolved writes correct schema
  test("emitApprovalResolved writes event with correct schema", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitApprovalResolved("tc-42", "bash", "allow-once", "session-99");

    expect(lines).toHaveLength(1);
    const event = parseLine(lines[0]!);
    expect(event.eventType).toBe("aegis.approval.resolved");
    expect(event.runtime).toBe("openclaw");
    expect(event.sessionId).toBe("session-99");
    const action = event.action as Record<string, unknown>;
    expect(action.kind).toBe("tool_call");
    expect(action.name).toBe("bash");
    const decision = event.decision as Record<string, unknown>;
    expect(decision.decision).toBe("allow-once");
    const context = event.context as Record<string, unknown>;
    expect(context.traceId).toBe("tc-42");
  });

  // 13. emitApprovalResolved defaults sessionId
  test("emitApprovalResolved defaults sessionId to empty string", () => {
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });

    emitter.emitApprovalResolved("tc-1", "rm", "deny");

    const event = parseLine(lines[0]!);
    expect(event.sessionId).toBe("");
  });

  // 14. emitApprovalResolved does not throw on write error
  test("emitApprovalResolved does not throw on write error", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    appendFileMock.mockImplementation(
      (_path: string, _data: string, cb: (err: Error | null) => void) => {
        cb(new Error("disk full"));
      },
    );

    const emitter = new AegisAuditEmitter({ auditLogPath: "test.jsonl" });
    expect(() => emitter.emitApprovalResolved("tc-1", "bash", "timeout")).not.toThrow();

    warnSpy.mockRestore();
  });

  // 15. Invalid regex pattern is skipped with warning
  test("invalid regex pattern is skipped with warning", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const lines = captureLines();
    const emitter = new AegisAuditEmitter({
      auditLogPath: "test.jsonl",
      redactValuePatterns: ["[invalid regex", "sk-[a-zA-Z0-9]+"],
    });

    const payload = makePayload({ toolArgs: { token: "sk-abc123" } });
    emitter.emitRequested(payload);

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Skipping invalid redact pattern"));
    const event = parseLine(lines[0]!);
    const action = event.action as Record<string, unknown>;
    const args = action.args as Record<string, unknown>;
    expect(args.token).toBe("[REDACTED]");

    warnSpy.mockRestore();
  });
});
