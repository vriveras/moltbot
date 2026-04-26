package aegis

import rego.v1

# =============================================================================
# Permissive Policy
# =============================================================================
# Development-friendly posture: allow most operations by default, but hard-deny
# known destructive patterns and dangerous network commands.
#
# Shell commands are allowed but run with network disabled via executionEnvelope.
# Use this in trusted dev environments where fast iteration matters more than
# locking down every action.
#
# Input schema: input.action.{kind, name, args, runtime, sessionId, cwd}
# Output schema: {permissionDecision, permissionDecisionReason, ruleName,
#                  executionEnvelope}
# =============================================================================

# ── Default: allow everything not explicitly matched ─────────────────────────

default result := {
	"permissionDecision": "allow",
	"permissionDecisionReason": "Permissive policy — allowed by default",
}

# ── Helper sets ──────────────────────────────────────────────────────────────

safe_tools := {"view", "glob", "grep", "report_intent"}

shell_tools := {"powershell", "bash"}

destructive_patterns := [
	"rm -rf",
	"Remove-Item.*-Recurse",
	"format c:",
	"mkfs",
	"drop\\s+table",
]

# Commands that reach outside the machine
dangerous_network_commands := ["curl ", "wget ", "Invoke-WebRequest", "Invoke-RestMethod", "iwr ", "irm "]

# ── Helper rules ─────────────────────────────────────────────────────────────

_command := cmd if {
	cmd := object.get(input.action.args, "command", "")
}

is_destructive if {
	some pattern in destructive_patterns
	regex.match(pattern, _command)
}

has_dangerous_network if {
	some kw in dangerous_network_commands
	contains(_command, kw)
}

# ── Deny rules ───────────────────────────────────────────────────────────────

# Destructive commands — hard deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Destructive commands are blocked by policy",
	"ruleName": "deny-destructive",
} if {
	input.action.name in shell_tools
	is_destructive
}

# Dangerous network commands inside shells — deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Outbound network commands are blocked by policy",
	"ruleName": "deny-network-command",
} if {
	input.action.name in shell_tools
	has_dangerous_network
}

# Direct network tools (web_fetch, curl, wget as tool names) — deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Direct network tools are blocked by policy",
	"ruleName": "deny-network-tool",
} if {
	input.action.name in {"web_fetch", "curl", "wget"}
}

# ── Allow rules (explicit for clarity, even though default is allow) ─────────

# Read-only tools — always safe
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

# File writes — allowed in permissive mode
result := {
	"permissionDecision": "allow",
	"ruleName": "allow-file-write",
} if {
	input.action.kind == "file_write"
}

# Shell commands — allowed, but with network disabled in the sandbox
result := {
	"permissionDecision": "allow",
	"ruleName": "allow-shell-no-network",
	"executionEnvelope": {"networkEnabled": false},
} if {
	input.action.name in shell_tools
	not is_destructive
	not has_dangerous_network
}
