package aegis

# =============================================================================
# Strict Policy
# =============================================================================
# Every tool call requires human approval, except for read-only operations.
# Use this in high-security environments where a human must explicitly approve
# every action that modifies state.
#
# This policy trades speed for safety — every write, execute, or network call
# will pause and wait for human confirmation.
# =============================================================================

# Strict default — every tool call requires human approval
default result = {
    "decision": "ask",
    "reason": "strict policy — all tool calls require approval"
}

# ---------------------------------------------------------------------------
# Allow rules — only truly read-only operations bypass approval
# ---------------------------------------------------------------------------

# Allow reading files without approval — no side effects
result = {"decision": "allow", "reason": "read-only — no approval needed"} {
    input.action.name == "read_file"
}

# Allow listing directories without approval — no side effects
result = {"decision": "allow", "reason": "read-only — no approval needed"} {
    input.action.name == "list_directory"
}

# Allow viewing file contents without approval
result = {"decision": "allow", "reason": "read-only — no approval needed"} {
    input.action.name == "view"
}

# Allow code search without approval
result = {"decision": "allow", "reason": "read-only — no approval needed"} {
    input.action.name == "grep"
}

result = {"decision": "allow", "reason": "read-only — no approval needed"} {
    input.action.name == "glob"
}

# ---------------------------------------------------------------------------
# Deny rules — some operations are never allowed, even with approval
# ---------------------------------------------------------------------------

# Unconditionally deny destructive commands — no approval can override
result = {"decision": "deny", "reason": "destructive command unconditionally blocked"} {
    input.action.name == "bash"
    contains(input.action.args.command, "rm -rf /")
}
