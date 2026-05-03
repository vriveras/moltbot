/**
 * Tests for MXC_ISOLATION_SESSION=1 skip-wrap behavior in enforceAegisSandbox.
 *
 * These tests mock node:net to simulate daemon IPC responses, allowing us to
 * verify that cookie redemption still happens (audit trail) but wxc-exec
 * wrapping is skipped when the outer MXC isolation session is active.
 *
 * DoD-7, DoD-19
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import type { ResolvedAegisEnforcementConfig } from "./aegis-config.js";

// ---------------------------------------------------------------------------
// Mock node:net to intercept daemon pipe connections
// ---------------------------------------------------------------------------

class MockSocket extends EventEmitter {
  destroyed = false;

  constructor(private responsePayload: string) {
    super();
  }

  write(_data: string): boolean {
    // Simulate async daemon response
    process.nextTick(() => {
      this.emit("data", Buffer.from(this.responsePayload + "\n"));
    });
    return true;
  }

  destroy(): void {
    this.destroyed = true;
  }
}

let nextMockResponse = '{"valid":true,"envelope":{"timeoutSeconds":30,"networkEnabled":false,"readwritePaths":["/workspace"]}}';

vi.mock("node:net", () => ({
  connect: vi.fn((_opts: unknown) => {
    const sock = new MockSocket(nextMockResponse);
    process.nextTick(() => sock.emit("connect"));
    return sock;
  }),
}));

vi.mock("../logger.js", () => ({
  logWarn: vi.fn(),
  logInfo: vi.fn(),
}));

// Import AFTER mocks are set up
const { enforceAegisSandbox, AegisEnforcementError } = await import(
  "./aegis-sandbox-enforcement.js"
);

const mockConfig: ResolvedAegisEnforcementConfig = {
  aegisBinaryPath: "/nonexistent/aegis",
  mxcBinaryPath: "/nonexistent/wxc-exec",
  enabled: true,
  daemonPipePath: "\\\\.\\pipe\\aegis-test-mock",
};

const baseMeta = {
  aegisCookie: "test-cookie-isolation",
  aegisRedeemContext: { toolName: "system.run", args: "echo hello", cwd: "/tmp" },
};

// ---------------------------------------------------------------------------
// MXC_ISOLATION_SESSION skip-wrap tests
// ---------------------------------------------------------------------------

describe("enforceAegisSandbox: MXC_ISOLATION_SESSION", () => {
  const savedEnv = process.env.MXC_ISOLATION_SESSION;

  beforeEach(() => {
    nextMockResponse = JSON.stringify({
      valid: true,
      envelope: {
        timeoutSeconds: 30,
        networkEnabled: false,
        readwritePaths: ["/workspace"],
      },
    });
  });

  afterEach(() => {
    if (savedEnv === undefined) {
      delete process.env.MXC_ISOLATION_SESSION;
    } else {
      process.env.MXC_ISOLATION_SESSION = savedEnv;
    }
  });

  it("returns original argv with enforced=true when MXC_ISOLATION_SESSION=1", async () => {
    process.env.MXC_ISOLATION_SESSION = "1";

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: ["echo", "hello"],
      cwd: "/tmp",
    });

    expect(result.argv).toEqual(["echo", "hello"]);
    expect(result.enforced).toBe(true);
  });

  it("still redeems cookie (audit trail) before returning unwrapped argv", async () => {
    process.env.MXC_ISOLATION_SESSION = "1";
    const { connect } = await import("node:net");

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: ["ls", "-la"],
      cwd: "/home",
    });

    // connect was called = cookie was sent to daemon
    expect(connect).toHaveBeenCalled();
    expect(result.enforced).toBe(true);
  });

  it("wraps with wxc-exec when MXC_ISOLATION_SESSION is not set", async () => {
    delete process.env.MXC_ISOLATION_SESSION;

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: ["echo", "hi"],
      cwd: "/tmp",
    });

    expect(result.enforced).toBe(true);
    expect(result.argv[0]).toBe(mockConfig.mxcBinaryPath);
    expect(result.argv).toContain("--config-base64");
  });

  it("wraps with wxc-exec when MXC_ISOLATION_SESSION='0' (only '1' skips)", async () => {
    process.env.MXC_ISOLATION_SESSION = "0";

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: ["pwd"],
      cwd: "/tmp",
    });

    expect(result.enforced).toBe(true);
    expect(result.argv[0]).toBe(mockConfig.mxcBinaryPath);
  });

  it("wraps with wxc-exec when MXC_ISOLATION_SESSION='true' (strict equality)", async () => {
    process.env.MXC_ISOLATION_SESSION = "true";

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: ["whoami"],
      cwd: "/tmp",
    });

    expect(result.enforced).toBe(true);
    expect(result.argv[0]).toBe(mockConfig.mxcBinaryPath);
  });

  it("throws on invalid cookie even when MXC_ISOLATION_SESSION=1 (fail-closed)", async () => {
    nextMockResponse = JSON.stringify({ valid: false, error: "cookie expired" });
    process.env.MXC_ISOLATION_SESSION = "1";

    await expect(
      enforceAegisSandbox({
        config: mockConfig,
        executionMetadata: {
          aegisCookie: "expired-cookie",
          aegisRedeemContext: { toolName: "system.run", args: "rm -rf /", cwd: "/tmp" },
        },
        argv: ["rm", "-rf", "/"],
        cwd: "/tmp",
      }),
    ).rejects.toThrow("Cookie redemption failed");
  });

  it("throws on empty envelope even when MXC_ISOLATION_SESSION=1", async () => {
    nextMockResponse = JSON.stringify({ valid: true, envelope: {} });
    process.env.MXC_ISOLATION_SESSION = "1";

    await expect(
      enforceAegisSandbox({
        config: mockConfig,
        executionMetadata: {
          aegisCookie: "empty-envelope-cookie",
          aegisRedeemContext: { toolName: "system.run", args: "echo", cwd: "/tmp" },
        },
        argv: ["echo"],
        cwd: "/tmp",
      }),
    ).rejects.toThrow("empty execution envelope");
  });

  it("preserves original argv exactly (no mutation)", async () => {
    process.env.MXC_ISOLATION_SESSION = "1";
    const originalArgv = ["node", "--max-old-space-size=4096", "app.js", "--flag=value"];

    const result = await enforceAegisSandbox({
      config: mockConfig,
      executionMetadata: { ...baseMeta },
      argv: originalArgv,
      cwd: "/workspace",
    });

    expect(result.argv).toEqual(originalArgv);
    expect(result.argv).toBe(originalArgv); // same reference, not a copy
  });
});