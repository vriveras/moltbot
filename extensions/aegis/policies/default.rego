package aegis

# =============================================================================
# Default Deny Policy
# =============================================================================
# Baseline security posture: deny all tool calls unless an explicit allow rule
# matches. This is the recommended starting point for production environments.
#
# Usage: copy to .aegis/policy.rego and add allow rules for your workflow.
# =============================================================================

# Default deny — all tool calls require explicit allow rules
default result = {
    "decision": "deny",
    "reason": "No matching allow rule — default deny policy"
}

# ---------------------------------------------------------------------------
# Allow rules — add your own below
# ---------------------------------------------------------------------------

# Allow reading files — no side effects, safe by default
result = {"decision": "allow", "reason": "read-only file operation"} {
    input.action.name == "read_file"
}

# Allow listing directories — no side effects, safe by default
result = {"decision": "allow", "reason": "read-only file operation"} {
    input.action.name == "list_directory"
}

# Allow viewing file contents
result = {"decision": "allow", "reason": "read-only file operation"} {
    input.action.name == "view"
}

# Allow code search operations
result = {"decision": "allow", "reason": "read-only search operation"} {
    input.action.name == "grep"
}

result = {"decision": "allow", "reason": "read-only search operation"} {
    input.action.name == "glob"
}
