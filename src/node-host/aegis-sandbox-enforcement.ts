import { connect, type Socket } from "node:net";
import { userInfo } from "node:os";
import crypto from "node:crypto";
import type { ResolvedAegisEnforcementConfig } from "./aegis-config.js";
import {
  translateEnvelopeToPolicy,
  type AegisExecutionEnvelope,
  type SandboxPolicyLike,
} from "../shared/aegis-envelope.js";
import { logWarn } from "../logger.js";

const AEGIS_PIPE_PREFIX = "aegis-";
const REDEEM_TIMEOUT_MS = 3_000;
const MAX_RESPONSE_BYTES = 65_536; // 64KB - more than enough for any envelope

/**
 * Shell-quote an argv array into a single command-line string,
 * preserving argument boundaries.
 */
function shellQuoteArgv(argv: string[]): string {
  if (process.platform === "win32") {
    return argv
      .map((arg) => {
        if (/^[a-zA-Z0-9_./:=-]+$/.test(arg)) return arg;
        // Windows: wrap in double quotes, escape internal double-quotes
        const escaped = arg.replace(/"/g, '\\"');
        return `"${escaped}"`;
      })
      .join(" ");
  }
  // POSIX: single-quote each argument, escape embedded single quotes
  return argv
    .map((arg) => {
      if (/^[a-zA-Z0-9_./:=-]+$/.test(arg)) return arg;
      return "'" + arg.replace(/'/g, "'\\''") + "'";
    })
    .join(" ");
}

export type AegisEnforcementResult = {
  /** The (potentially wrapped) argv to execute. */
  argv: string[];
  /** Whether sandbox enforcement was applied. */
  enforced: boolean;
};

export class AegisEnforcementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AegisEnforcementError";
  }
}

type RedeemResponse = {
  valid: boolean;
  envelope?: AegisExecutionEnvelope;
  error?: string;
};

/** Compute the daemon pipe path matching Aegis daemon naming convention. */
function getDaemonPipePath(): string {
  const pipeName = `${AEGIS_PIPE_PREFIX}${userInfo().username}`;
  return process.platform === "win32"
    ? `\\\\.\\pipe\\${pipeName}`
    : `/tmp/CoreFxPipe_${pipeName}`;
}

/** Validate that a parsed value matches the expected RedeemResponse shape. */
function validateRedeemResponse(parsed: unknown): RedeemResponse {
  if (typeof parsed !== "object" || parsed === null) {
    throw new AegisEnforcementError("Aegis daemon returned non-object response");
  }
  if (typeof (parsed as Record<string, unknown>).valid !== "boolean") {
    throw new AegisEnforcementError("Aegis daemon response missing 'valid' field");
  }
  return parsed as RedeemResponse;
}

/**
 * Redeem a cookie via the Aegis daemon named pipe.
 *
 * Resource cleanup: All exit paths (timeout, error, data, close) go through the
 * `settle` helper which clears the timer and destroys the socket. The only
 * exception is a synchronous throw from `connect()` — in that case the timer
 * has not yet been created and no socket exists, so there is nothing to clean up.
 */
export function redeemCookie(params: {
  cookie: string;
  toolName: string;
  args: string;
  cwd?: string;
  pipePath?: string;
}): Promise<RedeemResponse> {
  return new Promise<RedeemResponse>((resolve, reject) => {
    let settled = false;
    let data = "";
    let socket: Socket;

    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket?.destroy();
      } catch {
        // ignore cleanup errors
      }
      fn();
    };

    try {
      socket = connect({ path: params.pipePath ?? getDaemonPipePath() });
    } catch (err) {
      logWarn(`aegis: failed to connect to daemon pipe: ${String(err)}`);
      reject(new AegisEnforcementError("Failed to connect to Aegis daemon"));
      return;
    }

    const timer = setTimeout(() => {
      settle(() =>
        reject(new AegisEnforcementError("Aegis daemon cookie redemption timed out")),
      );
    }, REDEEM_TIMEOUT_MS);

    socket.on("connect", () => {
      const request = JSON.stringify({
        redeem: params.cookie,
        toolName: params.toolName,
        args: params.args,
        cwd: params.cwd,
      });
      try {
        socket.write(request + "\n");
      } catch (err) {
        settle(() =>
          reject(new AegisEnforcementError(`Failed to send redeem request: ${String(err)}`)),
        );
      }
    });

    socket.on("data", (chunk: Buffer) => {
      data += chunk.toString();
      if (data.length > MAX_RESPONSE_BYTES) {
        settle(() =>
          reject(new AegisEnforcementError("Aegis daemon response exceeded maximum size")),
        );
        return;
      }
      const newlineIdx = data.indexOf("\n");
      if (newlineIdx !== -1) {
        const line = data.slice(0, newlineIdx).trim();
        settle(() => {
          try {
            const parsed = JSON.parse(line);
            resolve(validateRedeemResponse(parsed));
          } catch (err) {
            if (err instanceof AegisEnforcementError) {
              reject(err);
            } else {
              reject(new AegisEnforcementError("Invalid JSON in Aegis daemon redeem response"));
            }
          }
        });
      }
    });

    socket.on("error", (err) => {
      logWarn(`aegis: daemon connection error: ${err.message}`);
      settle(() =>
        reject(
          new AegisEnforcementError("Aegis daemon connection error"),
        ),
      );
    });

    socket.on("close", () => {
      settle(() => {
        if (data.trim()) {
          try {
            const parsed = JSON.parse(data.trim());
            resolve(validateRedeemResponse(parsed));
          } catch (err) {
            if (err instanceof AegisEnforcementError) {
              reject(err);
            } else {
              reject(
                new AegisEnforcementError("Invalid JSON in Aegis daemon redeem response"),
              );
            }
          }
        } else {
          reject(new AegisEnforcementError("Aegis daemon closed without response"));
        }
      });
    });
  });
}

/**
 * Build a minimal ContainerConfig for wxc-exec/lxc-exec.
 * Inline construction avoids importing @microsoft/mxc-sdk in core.
 */
function buildContainerConfigBase64(
  policy: SandboxPolicyLike,
  commandLine: string,
  cwd?: string,
): string {
  const config: Record<string, unknown> = {
    version: policy.version,
    containerId: `aegis-${crypto.randomUUID()}`,
    lifecycle: { destroyOnExit: true },
    process: {
      commandLine,
      cwd: cwd ?? undefined,
      timeout: policy.timeoutMs ?? 0,
    },
    network: {
      defaultPolicy:
        policy.network?.allowOutbound ? "allow" : "block",
    },
  };

  if (policy.filesystem) {
    config.filesystem = {
      readwritePaths: policy.filesystem.readwritePaths ?? [],
      readonlyPaths: policy.filesystem.readonlyPaths ?? [],
      deniedPaths: policy.filesystem.deniedPaths ?? [],
    };
  }

  return Buffer.from(JSON.stringify(config), "utf-8").toString("base64");
}

/**
 * Apply Aegis sandbox enforcement to the given command argv.
 *
 * Flow:
 * 1. Extract aegisCookie from executionMetadata
 * 2. Redeem cookie via daemon pipe → get ExecutionEnvelope
 * 3. Translate envelope → SandboxPolicy
 * 4. Build wxc-exec/lxc-exec wrapped argv
 *
 * Fail-closed: any error rejects the command.
 */
export async function enforceAegisSandbox(params: {
  config: ResolvedAegisEnforcementConfig;
  executionMetadata: Record<string, unknown>;
  argv: string[];
  cwd?: string;
}): Promise<AegisEnforcementResult> {
  const cookie = params.executionMetadata.aegisCookie;
  if (typeof cookie !== "string" || !cookie) {
    throw new AegisEnforcementError(
      "executionMetadata.aegisCookie is missing or not a string",
    );
  }

  const commandLine = shellQuoteArgv(params.argv);

  logWarn(`aegis: redeeming cookie for sandbox enforcement`);

  const response = await redeemCookie({
    cookie,
    toolName: "system.run",
    args: commandLine,
    cwd: params.cwd,
    pipePath: params.config.daemonPipePath,
  });

  if (!response.valid) {
    throw new AegisEnforcementError(
      `Cookie redemption failed: ${response.error ?? "invalid or expired cookie"}`,
    );
  }

  if (!response.envelope || Object.keys(response.envelope).length === 0) {
    throw new AegisEnforcementError(
      "Aegis daemon returned empty execution envelope — cannot determine sandbox constraints",
    );
  }
  const envelope = response.envelope;
  const policy = translateEnvelopeToPolicy(envelope);
  const configBase64 = buildContainerConfigBase64(policy, commandLine, params.cwd);

  const wrappedArgv = [params.config.mxcBinaryPath, "--config-base64", configBase64];

  return {
    argv: wrappedArgv,
    enforced: true,
  };
}
