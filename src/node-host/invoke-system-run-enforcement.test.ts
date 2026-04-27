import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  vi,
} from "vitest";
import {
  clearRuntimeConfigSnapshot,
  getRuntimeConfigSnapshot,
} from "../config/runtime-snapshot.js";
import { resolveExecApprovalsPath } from "../infra/exec-approvals.js";
import type { ResolvedAegisEnforcementConfig } from "./aegis-config.js";
import { handleSystemRunInvoke } from "./invoke-system-run.js";
import type { HandleSystemRunInvokeOptions } from "./invoke-system-run.js";

vi.mock("../logger.js", () => ({
  logWarn: vi.fn(),
}));

type MockedRunCommand = Mock<HandleSystemRunInvokeOptions["runCommand"]>;
type MockedSendInvokeResult = Mock<HandleSystemRunInvokeOptions["sendInvokeResult"]>;
type MockedSendExecFinishedEvent = Mock<HandleSystemRunInvokeOptions["sendExecFinishedEvent"]>;
type MockedSendNodeEvent = Mock<HandleSystemRunInvokeOptions["sendNodeEvent"]>;

const FAKE_AEGIS_CONFIG: ResolvedAegisEnforcementConfig = {
  aegisBinaryPath: "/nonexistent/aegis-test-binary",
  mxcBinaryPath: "/nonexistent/wxc-exec-test-binary",
  enabled: true,
};

describe("handleSystemRunInvoke Aegis sandbox enforcement E2E wiring", () => {
  let fixtureRoot = "";
  let openClawHome = "";
  let previousOpenClawHome: string | undefined;

  beforeAll(() => {
    fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-aegis-enforcement-"));
    openClawHome = path.join(fixtureRoot, "openclaw-home");
    fs.mkdirSync(openClawHome, { recursive: true });
  });

  afterAll(() => {
    if (fixtureRoot) {
      fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  beforeEach(() => {
    previousOpenClawHome = process.env.OPENCLAW_HOME;
    process.env.OPENCLAW_HOME = openClawHome;
    fs.rmSync(resolveExecApprovalsPath(), { force: true });
    clearRuntimeConfigSnapshot();
  });

  afterEach(() => {
    clearRuntimeConfigSnapshot();
    if (previousOpenClawHome === undefined) {
      delete process.env.OPENCLAW_HOME;
    } else {
      process.env.OPENCLAW_HOME = previousOpenClawHome;
    }
  });

  function createLocalRunResult(stdout = "local-ok") {
    return {
      success: true,
      stdout,
      stderr: "",
      timedOut: false,
      truncated: false,
      exitCode: 0,
      error: null,
    };
  }

  async function runSystemInvoke(params: {
    command?: string[];
    executionMetadata?: Record<string, unknown> | null;
    security?: "full" | "allowlist";
    aegisEnforcementConfig?: ResolvedAegisEnforcementConfig | null;
  }): Promise<{
    runCommand: MockedRunCommand;
    sendInvokeResult: MockedSendInvokeResult;
    sendNodeEvent: MockedSendNodeEvent;
    sendExecFinishedEvent: MockedSendExecFinishedEvent;
  }> {
    const runCommand: MockedRunCommand = vi.fn(async () => createLocalRunResult());
    const sendInvokeResult: MockedSendInvokeResult = vi.fn(async () => {});
    const sendNodeEvent: MockedSendNodeEvent = vi.fn(async () => {});
    const sendExecFinishedEvent: MockedSendExecFinishedEvent = vi.fn(async () => {});

    await handleSystemRunInvoke({
      client: {} as never,
      params: {
        command: params.command ?? ["echo", "ok"],
        approved: false,
        sessionKey: "agent:main:main",
        ...(params.executionMetadata !== undefined
          ? { executionMetadata: params.executionMetadata }
          : {}),
      },
      skillBins: { current: async () => [] },
      execHostEnforced: false,
      execHostFallbackAllowed: true,
      resolveExecSecurity: () => params.security ?? "full",
      resolveExecAsk: () => "off",
      isCmdExeInvocation: () => false,
      sanitizeEnv: () => undefined,
      runCommand,
      runViaMacAppExecHost: vi.fn(async () => null),
      sendNodeEvent,
      buildExecEventPayload: (payload) => payload,
      sendInvokeResult,
      sendExecFinishedEvent,
      preferMacAppExecHost: false,
      loadConfig: () => getRuntimeConfigSnapshot() ?? {},
      aegisEnforcementConfig: params.aegisEnforcementConfig,
    });

    return { runCommand, sendInvokeResult, sendNodeEvent, sendExecFinishedEvent };
  }

  it("denies command when Aegis enforcement configured but daemon unreachable", async () => {
    const invoke = await runSystemInvoke({
      command: ["echo", "should-not-run"],
      executionMetadata: { aegisCookie: "test-cookie-unreachable" },
      aegisEnforcementConfig: FAKE_AEGIS_CONFIG,
      security: "full",
    });

    expect(invoke.runCommand).not.toHaveBeenCalled();
    expect(invoke.sendInvokeResult).toHaveBeenCalledWith(
      expect.objectContaining({
        ok: false,
        error: expect.objectContaining({
          message: expect.stringContaining("AEGIS_ENFORCEMENT_FAILED"),
        }),
      }),
    );
    expect(invoke.sendNodeEvent).toHaveBeenCalledWith(
      expect.anything(),
      "exec.denied",
      expect.objectContaining({ reason: "security=deny" }),
    );
  });

  it("executes normally when no executionMetadata present even with Aegis config", async () => {
    const invoke = await runSystemInvoke({
      command: ["echo", "normal-execution"],
      aegisEnforcementConfig: FAKE_AEGIS_CONFIG,
      security: "full",
    });

    expect(invoke.runCommand).toHaveBeenCalledTimes(1);
    expect(invoke.sendInvokeResult).toHaveBeenCalledWith(
      expect.objectContaining({ ok: true }),
    );
  });

  it("denies command when executionMetadata has aegisCookie but Aegis enforcement not configured", async () => {
    const invoke = await runSystemInvoke({
      command: ["echo", "passthrough-execution"],
      executionMetadata: { aegisCookie: "test-cookie-no-config" },
      // aegisEnforcementConfig not set → enforcement missing → deny
      security: "full",
    });

    expect(invoke.runCommand).not.toHaveBeenCalled();
    expect(invoke.sendInvokeResult).toHaveBeenCalledWith(
      expect.objectContaining({
        ok: false,
        error: expect.objectContaining({
          message: expect.stringContaining("AEGIS_ENFORCEMENT_MISSING"),
        }),
      }),
    );
    expect(invoke.sendNodeEvent).toHaveBeenCalledWith(
      expect.anything(),
      "exec.denied",
      expect.objectContaining({ reason: "security=deny" }),
    );
  });
});
