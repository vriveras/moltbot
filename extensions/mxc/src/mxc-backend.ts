import { execFileSync } from "node:child_process";
import {
  createConfigFromPolicy,
  type ContainerConfig,
} from "@microsoft/mxc-sdk";
import type {
  SandboxBackendHandle,
  SandboxBackendExecSpec,
  SandboxBackendCommandParams,
  SandboxBackendCommandResult,
  CreateSandboxBackendParams,
  SandboxBackendManager,
} from "openclaw/plugin-sdk/sandbox";
import type { MxcConfig } from "./config.js";
import { extractExecutionContext, TicketVerificationError } from "./ticket-bridge.js";
import { translateEnvelopeToPolicy } from "./envelope-translator.js";
import { resolveMxcBinaryPath } from "./binary-resolver.js";

/**
 * Serializes a ContainerConfig to base64 for passing to wxc-exec/lxc-exec.
 */
function configToBase64(config: ContainerConfig): string {
  return Buffer.from(JSON.stringify(config), "utf-8").toString("base64");
}

/**
 * Creates a SandboxBackendHandle for a specific session.
 */
export function createMxcSandboxBackendHandle(params: {
  binaryPath: string;
  config: MxcConfig;
  runtimeId: string;
  workdir: string;
}): SandboxBackendHandle {
  return {
    id: "mxc",
    runtimeId: params.runtimeId,
    runtimeLabel: `mxc-${params.runtimeId}`,
    workdir: params.workdir,

    async buildExecSpec({ command, workdir, env, usePty, executionMetadata }): Promise<SandboxBackendExecSpec> {
      if (!executionMetadata) {
        throw new TicketVerificationError(
          "MXC backend requires executionMetadata with Aegis envelope or signed ticket.",
        );
      }

      // Verify ticket / extract envelope
      const ctx = extractExecutionContext(executionMetadata, params.config.aegisPublicKeyPath);

      // Translate envelope → SandboxPolicy
      const policy = translateEnvelopeToPolicy(ctx.envelope);

      // Create ContainerConfig from policy
      const containerConfig = createConfigFromPolicy(
        policy,
        params.config.defaultContainment,
      );

      // Set command and working directory
      containerConfig.process!.commandLine = command;
      containerConfig.process!.cwd = workdir ?? params.workdir;

      // Build argv for wxc-exec/lxc-exec
      const argv = [params.binaryPath, "--config-base64", configToBase64(containerConfig)];
      if (params.config.debug) {
        argv.push("--debug");
      }

      return {
        argv,
        env: { ...process.env, ...env } as NodeJS.ProcessEnv,
        stdinMode: usePty ? "pipe-open" : "pipe-closed",
      };
    },

    async finalizeExec() {
      // MXC containers are ephemeral (lifecycle.destroyOnExit=true) — no cleanup needed
    },

    async runShellCommand(cmdParams: SandboxBackendCommandParams): Promise<SandboxBackendCommandResult> {
      // Shell commands run with a restrictive default policy (no network, 30s timeout)
      const policy = translateEnvelopeToPolicy({
        networkEnabled: false,
        timeoutSeconds: 30,
      });
      const containerConfig = createConfigFromPolicy(policy, params.config.defaultContainment);
      containerConfig.process!.commandLine = cmdParams.script;

      const args = ["--config-base64", configToBase64(containerConfig)];
      if (params.config.debug) args.push("--debug");

      try {
        const result = execFileSync(params.binaryPath, args, {
          input: cmdParams.stdin,
          timeout: 30_000,
          maxBuffer: 10 * 1024 * 1024,
          signal: cmdParams.signal ?? undefined,
        });
        return { stdout: Buffer.from(result), stderr: Buffer.alloc(0), code: 0 };
      } catch (err: unknown) {
        const execErr = err as { stdout?: Buffer; stderr?: Buffer; status?: number };
        if (cmdParams.allowFailure) {
          return {
            stdout: Buffer.from(execErr.stdout ?? ""),
            stderr: Buffer.from(execErr.stderr ?? ""),
            code: execErr.status ?? 1,
          };
        }
        throw err;
      }
    },
  };
}

/** Factory function — called by OpenClaw when sandbox.backend=mxc */
export function createMxcSandboxBackendFactory(config: MxcConfig) {
  return async function createMxcSandboxBackend(
    params: CreateSandboxBackendParams,
  ): Promise<SandboxBackendHandle> {
    const binaryPath = resolveMxcBinaryPath(config.mxcBinaryPath);
    const runtimeId = `${params.sessionKey}-${params.scopeKey}`;
    return createMxcSandboxBackendHandle({
      binaryPath,
      config,
      runtimeId,
      workdir: params.workspaceDir,
    });
  };
}

/** Manager — enables `openclaw sandbox list` and `openclaw sandbox remove` */
export const mxcSandboxBackendManager: SandboxBackendManager = {
  async describeRuntime() {
    return {
      running: true,
      actualConfigLabel: "mxc-process",
      configLabelMatch: true,
    };
  },
  async removeRuntime() {
    // MXC containers are ephemeral — destroyed on exit automatically
  },
};
