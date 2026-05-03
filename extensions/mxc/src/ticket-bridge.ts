import * as fs from "node:fs";
import { connect, type Socket } from "node:net";
import { userInfo } from "node:os";
import {
  verifyTicket,
  type SignedTicket,
} from "@microsoft/mxc-sdk";
import type { MxcExecutionContext, AegisExecutionEnvelope } from "./types.js";

const AEGIS_PIPE_PREFIX = "aegis-";
const REDEEM_TIMEOUT_MS = 3_000;

export class TicketVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TicketVerificationError";
  }
}

export function getDaemonPipePath(): string {
  const envOverride = process.env.AEGIS_DAEMON_PIPE_PATH;
  if (envOverride) return envOverride;
  const pipeName = `${AEGIS_PIPE_PREFIX}${userInfo().username}`;
  return process.platform === "win32"
    ? `\\\\.\\pipe\\${pipeName}`
    : `/tmp/CoreFxPipe_${pipeName}`;
}

/**
 * Redeem a cookie via the Aegis daemon named pipe.
 * Returns the execution envelope on success.
 */
async function redeemCookie(params: {
  cookie: string;
  toolName: string;
  args: string;
  cwd?: string;
}): Promise<AegisExecutionEnvelope> {
  return new Promise<AegisExecutionEnvelope>((resolve, reject) => {
    let settled = false;
    let data = "";
    let socket: Socket;

    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket?.destroy(); } catch { /* ignore */ }
      fn();
    };

    try {
      socket = connect({ path: getDaemonPipePath() });
    } catch (err) {
      reject(new TicketVerificationError(`Failed to connect to Aegis daemon pipe: ${err}`));
      return;
    }

    const timer = setTimeout(() => {
      settle(() => reject(new TicketVerificationError("Aegis daemon redemption timed out")));
    }, REDEEM_TIMEOUT_MS);

    socket.on("connect", () => {
      const request = JSON.stringify({
        redeem: params.cookie,
        toolName: params.toolName,
        args: params.args,
        cwd: params.cwd,
      });
      socket.write(request + "\n");
    });

    socket.on("data", (chunk: Buffer) => {
      data += chunk.toString();
      const newlineIdx = data.indexOf("\n");
      if (newlineIdx !== -1) {
        const line = data.slice(0, newlineIdx).trim();
        try {
          const response = JSON.parse(line) as { valid: boolean; envelope?: AegisExecutionEnvelope; error?: string };
          if (!response.valid) {
            settle(() => reject(new TicketVerificationError(
              `Cookie redemption failed: ${response.error ?? "invalid or expired cookie"}`
            )));
          } else if (!response.envelope || Object.keys(response.envelope).length === 0) {
            settle(() => reject(new TicketVerificationError(
              "Daemon returned empty execution envelope"
            )));
          } else {
            settle(() => resolve(response.envelope!));
          }
        } catch {
          settle(() => reject(new TicketVerificationError("Failed to parse daemon redemption response")));
        }
      }
    });

    socket.on("error", (err) => {
      settle(() => reject(new TicketVerificationError(`Daemon pipe error: ${err.message}`)));
    });

    socket.on("close", () => {
      if (!settled) {
        if (data.trim()) {
          try {
            const response = JSON.parse(data.trim()) as { valid: boolean; envelope?: AegisExecutionEnvelope; error?: string };
            if (response.valid && response.envelope) {
              settle(() => resolve(response.envelope!));
              return;
            }
          } catch { /* fall through */ }
        }
        settle(() => reject(new TicketVerificationError("Daemon pipe closed unexpectedly")));
      }
    });
  });
}

/**
 * Extract execution context from executionMetadata.
 *
 * Priority order:
 * 1. aegisSignedTicket — ECDSA-signed ticket (tamper-proof)
 * 2. aegisEnvelope — raw envelope (development / direct trust)
 * 3. aegisCookie — redeem via daemon pipe to get envelope
 * 4. Error — fail-closed
 */
export async function extractExecutionContext(
  executionMetadata: Record<string, unknown>,
  aegisPublicKeyPath?: string,
  command?: string,
  cwd?: string,
): Promise<MxcExecutionContext> {
  // Path 1: Signed ticket (preferred — tamper-proof)
  const signedTicket = executionMetadata.aegisSignedTicket as SignedTicket | undefined;
  if (signedTicket?.ticket && signedTicket?.signature) {
    let publicKeyPem: string | undefined;
    if (aegisPublicKeyPath) {
      publicKeyPem = fs.readFileSync(aegisPublicKeyPath, "utf-8");
    }
    const result = verifyTicket(signedTicket, publicKeyPem);
    if (!result.valid || !result.ticket) {
      throw new TicketVerificationError(
        `Signed ticket verification failed: ${result.error ?? "unknown error"}`,
      );
    }
    return {
      envelope: (result.ticket.envelope ?? {}) as AegisExecutionEnvelope,
      ticketToolName: result.ticket.toolName,
      ticketArgsHash: result.ticket.argsHash,
    };
  }

  // Path 2: Raw envelope (development fallback / trust-on-first-use)
  const rawEnvelope = executionMetadata.aegisEnvelope as AegisExecutionEnvelope | undefined;
  if (rawEnvelope) {
    return { envelope: rawEnvelope };
  }

  // Path 3: aegisCookie — redeem via daemon pipe
  if (executionMetadata.aegisCookie) {
    const cookie = executionMetadata.aegisCookie as string;
    const redeemCtx = executionMetadata.aegisRedeemContext as
      { toolName?: string; args?: string; cwd?: string } | undefined;
    const redeemToolName = redeemCtx?.toolName ?? "exec";
    const redeemArgs = redeemCtx?.args ?? command ?? "";
    const redeemCwd = redeemCtx?.cwd ?? cwd;
    console.info(`[mxc] Redeeming aegisCookie via daemon pipe...`);
    console.info(`[mxc] redeem payload: cookie=${cookie.slice(0, 8)}... toolName=${redeemToolName} args=${redeemArgs} cwd=${redeemCwd}`);
    console.info(`[mxc] redeemContext present: ${!!redeemCtx}, keys: ${redeemCtx ? Object.keys(redeemCtx).join(",") : "none"}`);
    const envelope = await redeemCookie({
      cookie,
      toolName: redeemToolName,
      args: redeemArgs,
      cwd: redeemCwd,
    });
    console.info(`[mxc] Cookie redeemed successfully — envelope received`);
    return { envelope };
  }

  // Path 4: No metadata at all → fail-closed
  throw new TicketVerificationError(
    "No aegisSignedTicket or aegisEnvelope found in executionMetadata. " +
    "Ensure the Aegis extension is enabled and the tool call was approved.",
  );
}
