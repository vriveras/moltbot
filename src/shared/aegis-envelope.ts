/**
 * Shared Aegis envelope types and MXC policy translation.
 * Used by both the MXC gateway extension and the node-host enforcement module.
 */

/** The envelope shape Aegis places inside executionMetadata. */
export type AegisExecutionEnvelope = {
  mode?: "reuse_shell" | "ephemeral" | "pool_by_profile";
  sandboxProfile?: string;
  timeoutSeconds?: number;
  networkEnabled?: boolean;
  allowLocalNetwork?: boolean;
  deniedPaths?: string[];
  readonlyPaths?: string[];
  readwritePaths?: string[];
};

/** Extracted execution context from a verified ticket or raw envelope. */
export type MxcExecutionContext = {
  envelope: AegisExecutionEnvelope;
  ticketToolName?: string;
  ticketArgsHash?: string;
};

/**
 * MXC sandbox policy shape. Defined inline to avoid importing @microsoft/mxc-sdk
 * in contexts where it may not be available (e.g., node-host).
 */
export type SandboxPolicyLike = {
  version: string;
  timeoutMs?: number;
  network?: {
    allowOutbound?: boolean;
    allowLocalNetwork?: boolean;
  };
  filesystem?: {
    deniedPaths?: string[];
    readonlyPaths?: string[];
    readwritePaths?: string[];
  };
};

const POLICY_VERSION = "0.5.0-alpha";

/**
 * Translates an Aegis ExecutionEnvelope to an MXC SandboxPolicy.
 * Pure function — no side effects.
 */
export function translateEnvelopeToPolicy(envelope: AegisExecutionEnvelope): SandboxPolicyLike {
  const policy: SandboxPolicyLike = { version: POLICY_VERSION };

  if (envelope.timeoutSeconds != null && envelope.timeoutSeconds > 0) {
    policy.timeoutMs = envelope.timeoutSeconds * 1000;
  }

  if (envelope.networkEnabled != null || envelope.allowLocalNetwork != null) {
    policy.network = {
      allowOutbound: envelope.networkEnabled ?? false,
      allowLocalNetwork: envelope.allowLocalNetwork ?? false,
    };
  }

  const hasDenied = envelope.deniedPaths != null && envelope.deniedPaths.length > 0;
  const hasReadonly = envelope.readonlyPaths != null && envelope.readonlyPaths.length > 0;
  const hasReadwrite = envelope.readwritePaths != null && envelope.readwritePaths.length > 0;

  if (hasDenied || hasReadonly || hasReadwrite) {
    policy.filesystem = {};
    if (hasDenied) {
      policy.filesystem.deniedPaths = [...envelope.deniedPaths!];
    }
    if (hasReadonly) {
      policy.filesystem.readonlyPaths = [...envelope.readonlyPaths!];
    }
    if (hasReadwrite) {
      policy.filesystem.readwritePaths = [...envelope.readwritePaths!];
    }
  }

  return policy;
}
