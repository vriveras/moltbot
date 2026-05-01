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

      // Verify ticket / extract envelope (handles cookie redemption too)
      const ctx = await extractExecutionContext(executionMetadata, params.config.aegisPublicKeyPath, command, workdir);

      // Translate envelope → SandboxPolicy
      const policy = translateEnvelopeToPolicy(ctx.envelope);

      // Create ContainerConfig from policy
      // SDK currently only supports "process" containment; future types will be added
      const containerConfig = createConfigFromPolicy(
        policy,
        params.config.defaultContainment as "process",
      );

      // Wrap command with shell so built-ins (echo, cd, etc.) and pipes work.
      // CreateProcessInSandbox needs a full executable path — PATH resolution
      // may not work inside an AppContainer.
      const wrappedCommand = process.platform === "win32"
        ? `C:\\Windows\\System32\\cmd.exe /c ${command}`
        : `/bin/sh -c ${JSON.stringify(command)}`;
      containerConfig.process!.commandLine = wrappedCommand;

      const effectiveWorkdir = workdir ?? params.workdir;
      // BaseContainer may not ACL the cwd path before process creation.
      // Use a universally-accessible directory as cwd; the command itself
      // operates on absolute paths when it needs file access.
      containerConfig.process!.cwd = process.platform === "win32"
        ? "C:\\Windows\\System32"
        : effectiveWorkdir;

      // Ensure the sandbox can access the working directory for file operations
      if (effectiveWorkdir && !containerConfig.filesystem!.readwritePaths!.includes(effectiveWorkdir)) {
        containerConfig.filesystem!.readwritePaths!.push(effectiveWorkdir);
      }

      // Build argv for wxc-exec/lxc-exec
      const argv = [params.binaryPath, "--config-base64", configToBase64(containerConfig)];
      if (params.config.debug) {
        argv.push("--debug");
      }

      return {
        argv,
        env: { ...process.env, ...env } as NodeJS.ProcessEnv,
        stdinMode: usePty ? "pipe-open" : "pipe-closed",
        // AppContainer runner on Windows relies on console inheritance (ConPTY).
        // Without a PTY, stdout from the sandboxed process is lost.
        requirePty: process.platform === "win32",
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
      const containerConfig = createConfigFromPolicy(policy, params.config.defaultContainment as "process");
      containerConfig.process!.commandLine = cmdParams.script;

      const args = ["--config-base64", configToBase64(containerConfig)];
      if (params.config.debug) args.push("--debug");

      try {
        const result = execFileSync(params.binaryPath, args, {
          input: cmdParams.stdin,
          timeout: 30_000,
          maxBuffer: 10 * 1024 * 1024,
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
