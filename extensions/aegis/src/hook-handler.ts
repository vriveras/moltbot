import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisIpcClient } from "./ipc-client.js";
import type { AegisAuditEmitter } from "./audit-emitter.js";

export function registerAegisHooks(
  _api: OpenClawPluginApi,
  _getClient: () => AegisIpcClient,
  _emitter: AegisAuditEmitter,
): void {
  throw new Error("Not implemented");
}
