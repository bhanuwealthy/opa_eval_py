"""OPA policy evaluator using regorus."""

from typing import Any

class OpaEval:
    """An OPA policy evaluator backed by the regorus engine.

    Each instance is independent: it loads its own .rego file, optional
    external data, and remembers the Rego query to run on every call.

    Example::

        import opa_eval
        authz = opa_eval.OpaEval("authz.rego", query="data.authz.allow")
        result = authz.evaluate('{"role": "admin"}')
        parsed = authz.evaluate_parsed('{"role": "admin"}')
    """

    def __init__(
        self,
        policy_path: str,
        data_json: str | None = None,
        query: str | None = None,
    ) -> None:
        """Create a new OpaEval instance.

        Args:
            policy_path: Path to a .rego source file.
            data_json:   Optional JSON string providing external data (``data`` document).
            query:       Rego rule to evaluate on each call (default: ``"data"``).

        Raises:
            RuntimeError: If the policy file cannot be read or contains invalid syntax.
        """
        ...

    def evaluate(self, input_json: str) -> str:
        """Evaluate the policy with the given input and return a JSON string.

        Args:
            input_json: JSON-encoded input document.

        Returns:
            The evaluation result serialised as a JSON string.

        Raises:
            RuntimeError: If the input is not valid JSON or evaluation fails.
        """
        ...

    def evaluate_parsed(self, input_json: str) -> Any:
        """Evaluate the policy and return the result as a native Python object.

        Converts JSON to Python entirely in Rust, avoiding any ``json.loads`` overhead.

        Args:
            input_json: JSON-encoded input document.

        Returns:
            The evaluation result as a Python ``bool``, ``int``, ``float``,
            ``str``, ``list``, ``dict``, or ``None``.

        Raises:
            RuntimeError: If the input is not valid JSON or evaluation fails.
        """
        ...
