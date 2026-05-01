import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type { AegisIpcClient } from "./ipc-client.js";
import type { AegisAuditEmitter } from "./audit-emitter.js";
import type { AegisPluginConfig } from "./config.js";
import type { OpenClawActionPayload } from "./action-request.js";
import { buildApprovalRequest, handleApprovalResolution } from "./approval-bridge.js";
import { DEFAULT_FAIL_BEHAVIOR } from "./constants.js";

export function registerAegisHooks(
  api: OpenClawPluginApi,
  getClient: () => AegisIpcClient,
  emitter: AegisAuditEmitter,
  getConfig: () => AegisPluginConfig,
): void {
  api.on("before_tool_call", async (event, ctx) => {
    try {
      const config = getConfig();
      if (config.enabled === false) return;

      const failBehavior = config.failBehavior ?? DEFAULT_FAIL_BEHAVIOR;

      const payload: OpenClawActionPayload = {
        runtime: "openclaw",
        cwd: process.cwd(),
        toolName: event.toolName,
        toolArgs: event.params ?? {},
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        runId: event.runId ?? ctx.runId,
        toolCallId: event.toolCallId ?? ctx.toolCallId,
        timestamp: new Date().toISOString(),
      };

      const response = await getClient().decide(payload);

      emitter.emitRequested(payload);
      emitter.emitDecided(payload, response);

      if (response.permissionDecision === "allow") {
        // Build executionMetadata for MXC sandbox enforcement.
        // Priority: aegisEnvelope (direct, no redemption needed) > aegisCookie (fallback for node-host).
        const envelope = response.envelope ?? { mode: "reuse_shell" };
        const metadata: Record<string, unknown> = { aegisEnvelope: envelope };
        if (response.cookie) {
          metadata.aegisCookie = response.cookie;
          metadata.aegisRedeemContext = {
            toolName: event.toolName,
            args: JSON.stringify(event.params ?? {}),
            cwd: process.cwd(),
          };
        }
        console.info(`[aegis] allow — envelope.mode=${envelope.mode ?? "reuse_shell"} cookie=${response.cookie ? response.cookie.slice(0, 8) + "..." : "none"}`);
        return {
          block: false,
          executionMetadata: metadata,
        };
      }

      if (response.permissionDecision === "deny") {
        return {
          block: true,
          blockReason:
            response.permissionDecisionReason ?? "Denied by Aegis policy",
        };
      }

      if (response.permissionDecision === "ask") {
        const approval = buildApprovalRequest(
          event.toolName,
          event.params ?? {},
          response.permissionDecisionReason ?? "unknown",
          config,
        );
        return {
          requireApproval: {
            ...approval,
            onResolution: async (_resolution: unknown) => {
              const resolutionStr = String(_resolution);
              const result = handleApprovalResolution(resolutionStr, response.cookie);
              if (result.proceed) {
                // Note: The pre-issued cookie cannot be propagated through OpenClaw's
                // approval hook contract (onResolution returns void). If MXC sandbox
                // constraints are needed post-approval, a future SDK enhancement or
                // re-query mechanism is required.
                console.info(`[aegis] Approval granted for ${event.toolName}`);
              } else {
                console.info(`[aegis] Approval denied for ${event.toolName}: ${resolutionStr}`);
              }
              emitter.emitApprovalResolved(
                event.toolCallId ?? ctx.toolCallId ?? "",
                event.toolName,
                resolutionStr,
                ctx.sessionId,
              );
            },
          },
          // NO executionMetadata here — cookie should not leak before approval
        };
      }

      // Unrecognized decision values use failBehavior
      return { block: failBehavior === "deny" };
    } catch (err) {
      const failBehavior = getConfig().failBehavior ?? DEFAULT_FAIL_BEHAVIOR;
      console.error("[aegis] before_tool_call error:", err);
      return failBehavior === "deny"
        ? { block: true, blockReason: "Aegis extension error — fail-closed" }
        : { block: false };
    }
  });
}
