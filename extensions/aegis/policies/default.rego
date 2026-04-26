package aegis

import rego.v1

# =============================================================================
# Default Deny Policy
# =============================================================================
# Secure baseline posture: deny all actions unless an explicit rule matches.
# Recommended starting point for production environments.
#
# - Read-only tools and file reads are allowed unconditionally.
# - File writes and shell commands require human approval ("ask").
# - Destructive commands and network access are hard-denied.
#
# Input schema: input.action.{kind, name, args, runtime, sessionId, cwd}
# Output schema: {permissionDecision, permissionDecisionReason, ruleName,
#                  executionEnvelope}
# =============================================================================

# ── Default: deny everything not explicitly matched ──────────────────────────

default result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "No matching rule; default decision applied.",
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

# ── Helper rules ─────────────────────────────────────────────────────────────

_command := cmd if {
	cmd := object.get(input.action.args, "command", "")
}

is_destructive if {
	some pattern in destructive_patterns
	regex.match(pattern, _command)
}

is_network_tool if {
	input.action.name in {"web_fetch", "curl", "wget"}
}

is_network_command if {
	input.action.name in shell_tools
	some kw in ["curl ", "wget ", "Invoke-WebRequest", "Invoke-RestMethod", "iwr ", "irm "]
	contains(_command, kw)
}

# ── Deny rules (evaluated first by OPA conflict resolution) ──────────────────

# Destructive commands — hard deny, never allow
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Destructive commands are blocked by policy",
	"ruleName": "deny-destructive",
} if {
	input.action.name in shell_tools
	is_destructive
}

# Network access — hard deny
result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Network access is blocked by policy",
	"ruleName": "deny-network",
} if {
	is_network_tool
}

result := {
	"permissionDecision": "deny",
	"permissionDecisionReason": "Network access is blocked by policy",
	"ruleName": "deny-network-command",
} if {
	is_network_command
}

# ── Allow rules ──────────────────────────────────────────────────────────────

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

# ── Ask rules ────────────────────────────────────────────────────────────────

# File writes and creates require approval
result := {
	"permissionDecision": "ask",
	"permissionDecisionReason": "File modification requires approval",
	"ruleName": "ask-file-write",
} if {
	input.action.kind == "file_write"
	not is_destructive
}

# Shell commands require approval (unless already denied above)
result := {
	"permissionDecision": "ask",
	"permissionDecisionReason": "Shell command requires approval",
	"ruleName": "ask-shell",
} if {
	input.action.name in shell_tools
	not is_destructive
	not is_network_command
}
