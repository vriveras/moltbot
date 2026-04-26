package aegis

import rego.v1

# =============================================================================
# Strict Policy
# =============================================================================
# Enterprise / compliance posture: deny by default, allow only read-only
# operations, and require explicit human approval for everything else.
# Destructive commands are hard-denied — no approval can override them.
#
# All non-read actions run inside a tight executionEnvelope with network
# disabled and a reasonable timeout.
#
# Input schema: input.action.{kind, name, args, runtime, sessionId, cwd}
# Output schema: {permissionDecision, permissionDecisionReason, ruleName,
#                  executionEnvelope}
# =============================================================================

# ── Default: deny everything not explicitly matched ──────────────────────────

default result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "No matching rule; strict policy denies by default.",
}

# ── Helper sets ──────────────────────────────────────────────────────────────

safe_tools := {"view", "glob", "grep"}

shell_tools := {"powershell", "bash"}

destructive_patterns := [
	"rm -rf",
	"Remove-Item.*-Recurse",
	"format c:",
	"mkfs",
	"drop\\s+table",
]

# ── Helper rules ─────────────────────────────────────────────────────────────

_command := cmd if {
	cmd := object.get(input.action.args, "command", "")
}

_path := p if {
	p := object.get(input.action.args, "path", "<unknown>")
}

is_destructive if {
	some pattern in destructive_patterns
	regex.match(pattern, _command)
}

is_network_action if {
	input.action.name in {"web_fetch", "curl", "wget"}
}

is_network_command if {
	input.action.name in shell_tools
	some kw in ["curl ", "wget ", "Invoke-WebRequest", "Invoke-RestMethod", "iwr ", "irm "]
	contains(_command, kw)
}

# ── Tight execution envelope applied to all approved mutable actions ─────────

_strict_envelope := {
	"networkEnabled": false,
	"timeoutSeconds": 120,
}

# ── Deny rules ───────────────────────────────────────────────────────────────

# Destructive commands — hard deny, no approval possible
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Destructive commands are blocked by policy",
	"ruleName": "deny-destructive",
} if {
	input.action.name in shell_tools
	is_destructive
}

# Network tools — hard deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Network access is blocked by policy",
	"ruleName": "deny-network-tool",
} if {
	is_network_action
}

# Network commands inside shells — hard deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Network commands are blocked by policy",
	"ruleName": "deny-network-command",
} if {
	is_network_command
}

# ── Allow rules (read-only only) ─────────────────────────────────────────────

# Read-only tools — always safe, no approval needed
result := {
	"permissionDecision": "allow",
	"ruleName": "allow-safe-tools",
} if {
	input.action.kind == "tool_call"
	input.action.name in safe_tools
}

# File reads — always safe
result := {
	"permissionDecision": "allow",
	"ruleName": "allow-file-read",
} if {
	input.action.kind == "file_read"
}

# ── Ask rules (everything else requires human approval) ──────────────────────

# File writes require approval with path context
result := {
	"permissionDecision": "ask",
	"permissionDecisionReason": sprintf("File write requires approval — %s", [_path]),
	"ruleName": "ask-file-write",
	"executionEnvelope": _strict_envelope,
} if {
	input.action.kind == "file_write"
}

# Shell commands require approval (unless already denied above)
result := {
	"permissionDecision": "ask",
	"permissionDecisionReason": "Shell command requires approval",
	"ruleName": "ask-shell",
	"executionEnvelope": _strict_envelope,
} if {
	input.action.name in shell_tools
	not is_destructive
	not is_network_command
}
