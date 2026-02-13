"""OPA policy evaluator using regorus."""

from typing import Any

def load_policy(
    policy_path: str,
    data_json: str | None = None,
    query: str | None = None,
) -> None:
    """Load a .rego policy file. Call once at startup.

    Args:
        policy_path: Path to a .rego file.
        data_json:   Optional JSON string for external data.
        query:       Rego query to evaluate (default: "data").
    """
    ...

def evaluate(input_json: str) -> str:
    """Evaluate policy with input JSON string. Returns result as JSON string. Thread-safe."""
    ...

def evaluate_parsed(input_json: str) -> Any:
    """Evaluate policy and return parsed Python object (dict/list). Thread-safe."""
    ...
