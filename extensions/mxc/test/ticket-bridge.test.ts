import { afterEach, describe, expect, test, vi } from "vitest";

// Mock @microsoft/mxc-sdk verifyTicket before importing the module under test
const verifyTicketMock = vi.hoisted(() => vi.fn());

vi.mock("@microsoft/mxc-sdk", () => ({
  verifyTicket: verifyTicketMock,
}));

import { extractExecutionContext, TicketVerificationError, getDaemonPipePath } from "../src/ticket-bridge.js";
import type { AegisExecutionEnvelope } from "../src/types.js";

describe("extractExecutionContext", () => {
  test("valid signed ticket → returns execution context with envelope", () => {
    const mockEnvelope = {
      timeoutSeconds: 60,
      networkEnabled: false,
    };
    verifyTicketMock.mockReturnValue({
      valid: true,
      ticket: {
        toolName: "shell",
        argsHash: "abc123",
        envelope: mockEnvelope,
      },
    });

    const ctx = extractExecutionContext({
      aegisSignedTicket: {
        ticket: "dGVzdA==",
        signature: "c2ln",
        publicKey: "a2V5",
      },
    });

    expect(ctx.envelope).toEqual(mockEnvelope);
    expect(ctx.ticketToolName).toBe("shell");
    expect(ctx.ticketArgsHash).toBe("abc123");
  });

  test("invalid signature → throws TicketVerificationError", () => {
    verifyTicketMock.mockReturnValue({
      valid: false,
      error: "bad signature",
    });

    expect(() =>
      extractExecutionContext({
        aegisSignedTicket: {
          ticket: "dGVzdA==",
          signature: "bad",
          publicKey: "a2V5",
        },
      }),
    ).toThrow(TicketVerificationError);
  });

  test("raw aegisEnvelope fallback → returns context", () => {
    const envelope: AegisExecutionEnvelope = {
      networkEnabled: true,
      timeoutSeconds: 30,
    };
    const ctx = extractExecutionContext({ aegisEnvelope: envelope });

    expect(ctx.envelope).toEqual(envelope);
    expect(ctx.ticketToolName).toBeUndefined();
    expect(ctx.ticketArgsHash).toBeUndefined();
  });

  test("aegisCookie only (no envelope) → throws with redemption message", () => {
    expect(() =>
      extractExecutionContext({ aegisCookie: "cookie-abc" }),
    ).toThrow(/cookie redemption/i);
  });

  test("empty metadata → throws fail-closed error", () => {
    expect(() => extractExecutionContext({})).toThrow(TicketVerificationError);
    expect(() => extractExecutionContext({})).toThrow(
      /No aegisSignedTicket or aegisEnvelope/,
    );
  });
});

describe("getDaemonPipePath", () => {
  const ENV_KEY = "AEGIS_DAEMON_PIPE_PATH";

  afterEach(() => {
    delete process.env[ENV_KEY];
  });

  test("returns AEGIS_DAEMON_PIPE_PATH when set", () => {
    process.env[ENV_KEY] = "\\\\.\\pipe\\custom-test-pipe";
    expect(getDaemonPipePath()).toBe("\\\\.\\pipe\\custom-test-pipe");
  });

  test("falls back to username-based path when env var is unset", () => {
    delete process.env[ENV_KEY];
    const path = getDaemonPipePath();
    expect(path.length).toBeGreaterThan(0);
    if (process.platform === "win32") {
      expect(path).toMatch(/^\\\\.\\pipe\\aegis-/);
    } else {
      expect(path).toMatch(/^\/tmp\/CoreFxPipe_aegis-/);
    }
  });

  test("ignores empty string env var (falsy)", () => {
    process.env[ENV_KEY] = "";
    const path = getDaemonPipePath();
    if (process.platform === "win32") {
      expect(path).toMatch(/^\\\\.\\pipe\\aegis-/);
    } else {
      expect(path).toMatch(/^\/tmp\/CoreFxPipe_aegis-/);
    }
  });
});
