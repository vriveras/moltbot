export type NodeHostBrowserProxyConfig = {
  /** Enable the browser proxy on the node host (default: true). */
  enabled?: boolean;
  /** Optional allowlist of profile names exposed via the proxy; when set, create/delete profile routes are blocked on the proxy surface. */
  allowProfiles?: string[];
};

export type AegisEnforcementConfig = {
  /** Path to the Aegis CLI binary. When set, enables sandbox enforcement. */
  aegisBinaryPath?: string;
  /** Path to the MXC execution binary (wxc-exec on Windows, lxc-exec on Linux). */
  mxcBinaryPath?: string;
  /** Override the daemon named pipe path (for testing or non-standard deployments). */
  daemonPipePath?: string;
  /** Whether enforcement is enabled. Default: true when aegisBinaryPath is set. */
  enabled?: boolean;
};

export type NodeHostConfig = {
  /** Browser proxy settings for node hosts. */
  browserProxy?: NodeHostBrowserProxyConfig;
  /** Aegis sandbox enforcement configuration for node-host command execution. */
  aegisEnforcement?: AegisEnforcementConfig;
};
