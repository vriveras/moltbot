import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisAuditEmitter } from "./audit-emitter.js";

export function registerAegisAfterHooks(
  _api: OpenClawPluginApi,
  _emitter: AegisAuditEmitter,
): void {
  throw new Error("Not implemented");
}
