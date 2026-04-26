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
