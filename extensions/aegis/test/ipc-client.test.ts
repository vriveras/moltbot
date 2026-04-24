import { beforeEach, describe, expect, test, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";

// --- Mocks ---

const spawnMock = vi.hoisted(() =>
  vi.fn<(cmd: string, args: string[], opts: unknown) => ChildProcess>(),
);

vi.mock("node:child_process", () => ({
  spawn: spawnMock,
}));

import { AegisIpcClient } from "../src/ipc-client.js";

// --- Helpers ---

/** Build a fake ChildProcess with evented stdout/stderr/stdin. */
function createFakeChild(): ChildProcess & {
  _stdout: EventEmitter;
  _stderr: EventEmitter;
  _stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
  emitClose: (code: number | null) => void;
} {
  const proc = new EventEmitter() as ChildProcess & {
    _stdout: EventEmitter;
    _stderr: EventEmitter;
    _stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
    emitClose: (code: number | null) => void;
    killed: boolean;
    kill: ReturnType<typeof vi.fn>;
  };
  proc._stdout = new EventEmitter();
  proc._stderr = new EventEmitter();
  proc._stdin = { write: vi.fn(), end: vi.fn() };
  (proc as unknown as Record<string, unknown>).stdout = proc._stdout;
  (proc as unknown as Record<string, unknown>).stderr = proc._stderr;
  (proc as unknown as Record<string, unknown>).stdin = proc._stdin;
  proc.killed = false;
  proc.kill = vi.fn(() => {
    proc.killed = true;
    return true;
  });
  proc.emitClose = (code) => proc.emit("close", code);
  return proc;
}

function makePayload() {
  return {
    toolName: "bash",
    params: { command: "echo hi" },
    sessionId: "test-session",
    timestamp: new Date().toISOString(),
  };
}

function makeClient(overrides?: Partial<ConstructorParameters<typeof AegisIpcClient>[0]>) {
  return new AegisIpcClient({
    aegisBinaryPath: "/usr/bin/aegis",
    readTimeoutMs: 500,
    connectTimeoutMs: 500,
    ...overrides,
  });
}

// --- Tests ---

describe("AegisIpcClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  // 1. Successful decide — allow response
  test("decide returns parsed allow response from subprocess stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    // Simulate daemon writing allow response
    child._stdout.emit(
      "data",
      Buffer.from('{"action":"allow","reason":"policy matched"}\n'),
    );

    const result = await promise;
    expect(result.action).toBe("allow");
    expect(result.reason).toBe("policy matched");
  });

  // 2. Deny response
  test("decide returns parsed deny response from subprocess stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child._stdout.emit(
      "data",
      Buffer.from('{"action":"deny","reason":"blocked by policy","policyId":"p1"}\n'),
    );

    const result = await promise;
    expect(result.action).toBe("deny");
    expect(result.reason).toBe("blocked by policy");
    expect(result.policyId).toBe("p1");
  });

  // 3. Subprocess spawn failure — fail-closed deny
  test("decide returns fail-closed deny when spawn throws", async () => {
    spawnMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const client = makeClient();
    const result = await client.decide(makePayload());

    expect(result.action).toBe("deny");
    expect(result.reason).toContain("fail-closed");
  });

  // 4. Subprocess timeout — fail-closed deny
  test("decide returns fail-closed deny on timeout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient({ readTimeoutMs: 100 });
    const promise = client.decide(makePayload());

    // Advance past the timeout without writing to stdout
    vi.advanceTimersByTime(200);

    const result = await promise;
    expect(result.action).toBe("deny");
    expect(result.reason).toContain("fail-closed");
  });

  // 5. Malformed stdout — fail-closed deny
  test("decide returns fail-closed deny on malformed JSON stdout", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child._stdout.emit("data", Buffer.from("not-valid-json\n"));

    const result = await promise;
    expect(result.action).toBe("deny");
    expect(result.reason).toContain("fail-closed");
  });

  // 6. Subprocess error event — fail-closed deny
  test("decide returns fail-closed deny on child process error event", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.decide(makePayload());

    child.emit("error", new Error("spawn EACCES"));

    const result = await promise;
    expect(result.action).toBe("deny");
    expect(result.reason).toContain("fail-closed");
  });

  // 7. healthCheck success — exit code 0
  test("healthCheck resolves true when subprocess exits with code 0", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.healthCheck();

    child.emitClose(0);

    const result = await promise;
    expect(result).toBe(true);
    expect(spawnMock).toHaveBeenCalledWith(
      "/usr/bin/aegis",
      ["--version"],
      expect.anything(),
    );
  });

  // 8. healthCheck failure — non-zero exit code
  test("healthCheck resolves false when subprocess exits with non-zero code", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const promise = client.healthCheck();

    child.emitClose(1);

    const result = await promise;
    expect(result).toBe(false);
  });

  // 9. healthCheck — spawn throws
  test("healthCheck resolves false when spawn throws", async () => {
    spawnMock.mockImplementation(() => {
      throw new Error("ENOENT");
    });

    const client = makeClient();
    const result = await client.healthCheck();
    expect(result).toBe(false);
  });

  // 10. dispose cleans up active child processes
  test("dispose kills all tracked child processes", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();

    // Start a decide call so the child is tracked in activeChildren
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    client.decide(makePayload());

    client.dispose();

    expect(child.kill).toHaveBeenCalled();
  });

  // 11. decide writes payload JSON to child stdin
  test("decide writes JSON payload to subprocess stdin", async () => {
    const child = createFakeChild();
    spawnMock.mockReturnValue(child);

    const client = makeClient();
    const payload = makePayload();
    const promise = client.decide(payload);

    // Verify stdin received the payload
    expect(child._stdin.write).toHaveBeenCalledWith(
      JSON.stringify(payload) + "\n",
    );
    expect(child._stdin.end).toHaveBeenCalled();

    // Settle the promise
    child._stdout.emit("data", Buffer.from('{"action":"allow"}\n'));
    await promise;
  });
});
