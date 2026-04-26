import type { SandboxPolicy } from "@microsoft/mxc-sdk";
import type { AegisExecutionEnvelope } from "./types.js";

const POLICY_VERSION = "0.5.0-alpha";

/**
 * Translates an Aegis ExecutionEnvelope to an MXC SandboxPolicy.
 * Pure function — no side effects.
 */
export function translateEnvelopeToPolicy(envelope: AegisExecutionEnvelope): SandboxPolicy {
  const policy: SandboxPolicy = {
    version: POLICY_VERSION,
  };

  // Timeout: seconds → milliseconds
  if (envelope.timeoutSeconds != null && envelope.timeoutSeconds > 0) {
    policy.timeoutMs = envelope.timeoutSeconds * 1000;
  }

  // Network restrictions
  if (envelope.networkEnabled != null || envelope.allowLocalNetwork != null) {
    policy.network = {
      allowOutbound: envelope.networkEnabled ?? false,
      allowLocalNetwork: envelope.allowLocalNetwork ?? false,
    };
  }

  // Filesystem restrictions
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
