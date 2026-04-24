import type { OpenClawPluginService } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisPluginConfig } from "./config.js";

export type AegisDaemonServiceOptions = {
  config: AegisPluginConfig;
};

export function createAegisDaemonService(
  _options: AegisDaemonServiceOptions,
): OpenClawPluginService {
  throw new Error("Not implemented");
}
