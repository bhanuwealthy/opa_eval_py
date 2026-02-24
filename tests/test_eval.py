import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest

import opa_eval

POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.rego")


@pytest.fixture
def policy():
    return opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")


# ── Basic allow / deny ────────────────────────────────────

class TestBasicAuthz:
    def test_admin_allowed(self, policy):
        assert policy.evaluate_parsed(json.dumps({"role": "admin"})) is True

    def test_editor_read_allowed(self, policy):
        assert policy.evaluate_parsed(
            json.dumps({"role": "editor", "action": "read"})
        ) is True

    def test_editor_write_denied(self, policy):
        assert policy.evaluate_parsed(
            json.dumps({"role": "editor", "action": "write"})
        ) is False

    def test_viewer_denied(self, policy):
        assert policy.evaluate_parsed(json.dumps({"role": "viewer"})) is False

    def test_empty_input_denied(self, policy):
        assert policy.evaluate_parsed("{}") is False

    def test_no_role_denied(self, policy):
        assert policy.evaluate_parsed(json.dumps({"action": "read"})) is False


# ── evaluate() returns valid JSON string ──────────────────

class TestEvaluateRaw:
    def test_returns_string(self, policy):
        result = policy.evaluate(json.dumps({"role": "admin"}))
        assert isinstance(result, str)

    def test_result_is_valid_json(self, policy):
        result = policy.evaluate(json.dumps({"role": "admin"}))
        parsed = json.loads(result)
        assert parsed is True

    def test_false_result_is_valid_json(self, policy):
        result = policy.evaluate(json.dumps({"role": "nobody"}))
        parsed = json.loads(result)
        assert parsed is False


# ── External data ─────────────────────────────────────────

DATA_POLICY = """\
package rbac

import rego.v1

default allow := false

allow if {
    role := data.roles[input.user]
    role == "admin"
}
"""


class TestExternalData:
    def test_data_driven_allow(self):
        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write(DATA_POLICY)
            f.flush()
            rbac_policy = opa_eval.OpaEval(
                f.name,
                data_json=json.dumps({"roles": {"alice": "admin", "bob": "viewer"}}),
                query="data.rbac.allow",
            )
        assert rbac_policy.evaluate_parsed(json.dumps({"user": "alice"})) is True
        assert rbac_policy.evaluate_parsed(json.dumps({"user": "bob"})) is False
        assert rbac_policy.evaluate_parsed(json.dumps({"user": "unknown"})) is False
        os.unlink(f.name)


# ── Error handling ────────────────────────────────────────

class TestErrors:
    def test_missing_policy_file(self):
        with pytest.raises(RuntimeError, match="failed to read"):
            opa_eval.OpaEval("/nonexistent/policy.rego")

    def test_invalid_policy_syntax(self):
        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write("not valid rego !!!")
            f.flush()
            with pytest.raises(RuntimeError, match="invalid policy"):
                opa_eval.OpaEval(f.name)
        os.unlink(f.name)

    def test_invalid_input_json(self, policy):
        with pytest.raises(RuntimeError):
            policy.evaluate("not json")


# ── Thread safety ─────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_evaluations(self, policy):
        inputs = [
            ({"role": "admin"}, True),
            ({"role": "editor", "action": "read"}, True),
            ({"role": "editor", "action": "write"}, False),
            ({"role": "viewer"}, False),
        ]

        def eval_one(pair):
            inp, expected = pair
            result = policy.evaluate_parsed(json.dumps(inp))
            assert result is expected
            return True

        with ThreadPoolExecutor(max_workers=4) as pool:
            # run each case 10 times across threads
            results = list(pool.map(eval_one, inputs * 10))
        assert all(results)


# ── Multiple independent instances ────────────────────────

class TestMultipleInstances:
    def test_two_instances_are_independent(self):
        """Two OpaEval instances evaluate against their own policy independently."""
        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write(DATA_POLICY)
            f.flush()
            rbac_policy = opa_eval.OpaEval(
                f.name,
                data_json=json.dumps({"roles": {"alice": "admin"}}),
                query="data.rbac.allow",
            )

        authz_policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")

        # rbac instance resolves by user lookup against external data
        assert rbac_policy.evaluate_parsed(json.dumps({"user": "alice"})) is True
        # authz instance resolves by role field -- unaffected by rbac instance
        assert authz_policy.evaluate_parsed(json.dumps({"role": "admin"})) is True
        # cross-check: authz instance does not understand rbac inputs
        assert authz_policy.evaluate_parsed(json.dumps({"user": "alice"})) is False

        os.unlink(f.name)
