import * as fs from "node:fs";
import {
  verifyTicket,
  type SignedTicket,
} from "@microsoft/mxc-sdk";
import type { MxcExecutionContext, AegisExecutionEnvelope } from "./types.js";

export class TicketVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TicketVerificationError";
  }
}

/**
 * Extract execution context from executionMetadata.
 *
 * Priority order:
 * 1. aegisSignedTicket — ECDSA-signed ticket (tamper-proof)
 * 2. aegisEnvelope — raw envelope (development / direct trust)
 * 3. Error — fail-closed
 */
export function extractExecutionContext(
  executionMetadata: Record<string, unknown>,
  aegisPublicKeyPath?: string,
): MxcExecutionContext {
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
      envelope: result.ticket.envelope ?? {},
      ticketToolName: result.ticket.toolName,
      ticketArgsHash: result.ticket.argsHash,
    };
  }

  // Path 2: Raw envelope (development fallback / trust-on-first-use)
  const rawEnvelope = executionMetadata.aegisEnvelope as AegisExecutionEnvelope | undefined;
  if (rawEnvelope) {
    return { envelope: rawEnvelope };
  }

  // Path 3: aegisCookie present but no envelope — caller needs to redeem cookie first (P1)
  if (executionMetadata.aegisCookie) {
    throw new TicketVerificationError(
      "aegisCookie found but no aegisSignedTicket or aegisEnvelope. " +
      "Cookie redemption is not yet implemented (P1). " +
      "Configure Aegis to include aegisEnvelope or aegisSignedTicket in executionMetadata.",
    );
  }

  // Path 4: No metadata at all → fail-closed
  throw new TicketVerificationError(
    "No aegisSignedTicket or aegisEnvelope found in executionMetadata. " +
    "Ensure the Aegis extension is enabled and the tool call was approved.",
  );
}
