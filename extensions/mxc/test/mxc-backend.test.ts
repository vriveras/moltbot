import { describe, expect, test, vi } from "vitest";

// Mock dependencies
const createConfigFromPolicyMock = vi.hoisted(() =>
  vi.fn().mockReturnValue({
    version: "0.5.0-alpha",
    containerId: "test-id",
    process: { commandLine: "", timeout: 0 },
    filesystem: { readwritePaths: [], readonlyPaths: [], deniedPaths: [] },
  }),
);

const extractExecutionContextMock = vi.hoisted(() =>
  vi.fn().mockReturnValue({
    envelope: { timeoutSeconds: 30, networkEnabled: false },
  }),
);

vi.mock("@microsoft/mxc-sdk", () => ({
  createConfigFromPolicy: createConfigFromPolicyMock,
}));

vi.mock("../src/ticket-bridge.js", () => ({
  extractExecutionContext: extractExecutionContextMock,
  TicketVerificationError: class extends Error {
    constructor(msg: string) {
      super(msg);
      this.name = "TicketVerificationError";
    }
  },
}));

vi.mock("../src/envelope-translator.js", () => ({
  translateEnvelopeToPolicy: vi.fn().mockReturnValue({
    version: "0.5.0-alpha",
    timeoutMs: 30000,
    network: { allowOutbound: false, allowLocalNetwork: false },
  }),
}));

import { createMxcSandboxBackendHandle, mxcSandboxBackendManager } from "../src/mxc-backend.js";

describe("createMxcSandboxBackendHandle", () => {
  const baseParams = {
    binaryPath: "C:\\test\\wxc-exec.exe",
    config: {
      enabled: true,
      defaultContainment: "process" as const,
      debug: false,
    },
    runtimeId: "session-1-scope-1",
    workdir: "C:\\workspace",
  };

  test("buildExecSpec with valid metadata → returns argv with --config-base64", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    const spec = await handle.buildExecSpec({
      command: "echo hello",
      env: {},
      usePty: false,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    expect(spec.argv[0]).toBe("C:\\test\\wxc-exec.exe");
    expect(spec.argv[1]).toBe("--config-base64");
    expect(spec.argv.length).toBe(3);
    // The third element should be a valid base64 string
    expect(() => Buffer.from(spec.argv[2], "base64")).not.toThrow();
    expect(spec.stdinMode).toBe("pipe-closed");
  });

  test("buildExecSpec without metadata → throws", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    await expect(
      handle.buildExecSpec({
        command: "echo hello",
        env: {},
        usePty: false,
      }),
    ).rejects.toThrow(/executionMetadata/);
  });

  test("buildExecSpec with debug=true → argv includes --debug", async () => {
    const handle = createMxcSandboxBackendHandle({
      ...baseParams,
      config: { ...baseParams.config, debug: true },
    });
    const spec = await handle.buildExecSpec({
      command: "echo hello",
      env: {},
      usePty: false,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    expect(spec.argv).toContain("--debug");
  });

  test("handle has correct id, runtimeId, and workdir", () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    expect(handle.id).toBe("mxc");
    expect(handle.runtimeId).toBe("session-1-scope-1");
    expect(handle.workdir).toBe("C:\\workspace");
    expect(handle.runtimeLabel).toBe("mxc-session-1-scope-1");
  });

  test("usePty=true → stdinMode is pipe-open", async () => {
    const handle = createMxcSandboxBackendHandle(baseParams);
    const spec = await handle.buildExecSpec({
      command: "bash",
      env: {},
      usePty: true,
      executionMetadata: { aegisEnvelope: { timeoutSeconds: 30 } },
    });

    expect(spec.stdinMode).toBe("pipe-open");
  });
});

describe("mxcSandboxBackendManager", () => {
  test("describeRuntime returns running=true", async () => {
    const info = await mxcSandboxBackendManager.describeRuntime({
      entry: {} as never,
      config: {} as never,
    });
    expect(info.running).toBe(true);
    expect(info.configLabelMatch).toBe(true);
  });

  test("removeRuntime completes without error", async () => {
    await expect(
      mxcSandboxBackendManager.removeRuntime({
        entry: {} as never,
        config: {} as never,
      }),
    ).resolves.toBeUndefined();
  });
});
