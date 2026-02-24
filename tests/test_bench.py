import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import opa_eval

POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.rego")

DATA_POLICY = """\
package rbac

import rego.v1

default allow := false

allow if {
    role := data.roles[input.user]
    role == "admin"
}
"""

ROLES = {f"user{i}": ("admin" if i % 10 == 0 else "viewer") for i in range(100)}


# ── Single evaluation ─────────────────────────────────────

def test_evaluate_simple_allow(benchmark):
    policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(policy.evaluate, inp)


def test_evaluate_simple_deny(benchmark):
    policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "viewer"})
    benchmark(policy.evaluate, inp)


def test_evaluate_parsed(benchmark):
    policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(policy.evaluate_parsed, inp)


# ── With external data ────────────────────────────────────

def test_evaluate_with_data(benchmark):
    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
        f.write(DATA_POLICY)
        f.flush()
        policy = opa_eval.OpaEval(
            f.name,
            data_json=json.dumps({"roles": ROLES}),
            query="data.rbac.allow",
        )
    inp = json.dumps({"user": "user0"})
    benchmark(policy.evaluate, inp)
    os.unlink(f.name)


# ── Input size scaling ────────────────────────────────────

def test_evaluate_small_input(benchmark):
    policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(policy.evaluate, inp)


def test_evaluate_large_input(benchmark):
    policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin", "extra": {f"key{i}": f"val{i}" for i in range(100)}})
    benchmark(policy.evaluate, inp)


# ── OpaEval construction cost ─────────────────────────────

def test_construct_opa_eval(benchmark):
    benchmark(opa_eval.OpaEval, POLICY_PATH, query="data.authz.allow")


# ── Helpers ───────────────────────────────────────────────

def _throughput(fn, *, workers, duration_s=2.0):
    """Run `fn` across `workers` threads for `duration_s` and return ops/sec."""
    stop = threading.Event()
    counts = [0] * workers

    def worker(idx):
        c = 0
        while not stop.is_set():
            fn()
            c += 1
        counts[idx] = c

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(worker, i) for i in range(workers)]
        time.sleep(duration_s)
        stop.set()
        for f in futs:
            f.result()

    total = sum(counts)
    return total / duration_s


# ── Concurrent throughput ─────────────────────────────────

class TestConcurrentThroughput:
    """Sustained multi-thread throughput on a single OpaEval instance."""

    def test_throughput_1_thread(self):
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: policy.evaluate(inp), workers=1)
        print(f"\n  1 thread: {ops:,.0f} ops/sec")
        assert ops > 50_000

    def test_throughput_4_threads(self):
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: policy.evaluate(inp), workers=4)
        print(f"\n  4 threads: {ops:,.0f} ops/sec")
        assert ops > 100_000

    def test_throughput_8_threads(self):
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: policy.evaluate(inp), workers=8)
        print(f"\n  8 threads: {ops:,.0f} ops/sec")
        assert ops > 100_000

    def test_throughput_parsed_4_threads(self):
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: policy.evaluate_parsed(inp), workers=4)
        print(f"\n  4 threads (parsed): {ops:,.0f} ops/sec")
        assert ops > 80_000

    def test_throughput_with_data_4_threads(self):
        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write(DATA_POLICY)
            f.flush()
            policy = opa_eval.OpaEval(
                f.name,
                data_json=json.dumps({"roles": ROLES}),
                query="data.rbac.allow",
            )
        inp = json.dumps({"user": "user0"})
        ops = _throughput(lambda: policy.evaluate(inp), workers=4)
        print(f"\n  4 threads (data): {ops:,.0f} ops/sec")
        os.unlink(f.name)
        assert ops > 80_000


# ── Concurrent correctness ────────────────────────────────

class TestConcurrentCorrectness:
    """Verify results stay correct under heavy concurrent load on one instance."""

    def test_mixed_inputs_correctness(self):
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        cases = [
            (json.dumps({"role": "admin"}), True),
            (json.dumps({"role": "editor", "action": "read"}), True),
            (json.dumps({"role": "editor", "action": "write"}), False),
            (json.dumps({"role": "viewer"}), False),
            (json.dumps({}), False),
        ]
        errors = []
        stop = threading.Event()

        def worker():
            idx = 0
            while not stop.is_set():
                inp, expected = cases[idx % len(cases)]
                result = policy.evaluate_parsed(inp)
                if result is not expected:
                    errors.append((inp, expected, result))
                idx += 1

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(worker) for _ in range(8)]
            time.sleep(2.0)
            stop.set()
            for f in futs:
                f.result()

        assert errors == [], f"got {len(errors)} wrong results: {errors[:5]}"

    def test_concurrent_evaluate_and_evaluate_parsed(self):
        """Mix evaluate() and evaluate_parsed() calls on one instance concurrently."""
        policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")
        inp_allow = json.dumps({"role": "admin"})
        inp_deny = json.dumps({"role": "viewer"})
        errors = []
        stop = threading.Event()

        def worker():
            idx = 0
            while not stop.is_set():
                if idx % 2 == 0:
                    result = policy.evaluate_parsed(inp_allow)
                    if result is not True:
                        errors.append(("evaluate_parsed allow", result))
                else:
                    raw = policy.evaluate(inp_deny)
                    result = json.loads(raw)
                    if result is not False:
                        errors.append(("evaluate deny", result))
                idx += 1

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(worker) for _ in range(8)]
            time.sleep(2.0)
            stop.set()
            for f in futs:
                f.result()

        assert errors == [], f"got {len(errors)} wrong results: {errors[:5]}"

    def test_two_instances_concurrent(self):
        """Two independent OpaEval instances used concurrently produce correct results."""
        authz_policy = opa_eval.OpaEval(POLICY_PATH, query="data.authz.allow")

        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write(DATA_POLICY)
            f.flush()
            rbac_policy = opa_eval.OpaEval(
                f.name,
                data_json=json.dumps({"roles": ROLES}),
                query="data.rbac.allow",
            )

        errors = []
        stop = threading.Event()

        def authz_worker():
            inp = json.dumps({"role": "admin"})
            while not stop.is_set():
                result = authz_policy.evaluate_parsed(inp)
                if result is not True:
                    errors.append(("authz", result))

        def rbac_worker():
            inp = json.dumps({"user": "user0"})
            while not stop.is_set():
                result = rbac_policy.evaluate_parsed(inp)
                if result is not True:
                    errors.append(("rbac", result))

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(authz_worker) for _ in range(4)]
            futs += [pool.submit(rbac_worker) for _ in range(4)]
            time.sleep(2.0)
            stop.set()
            for fut in futs:
                fut.result()

        os.unlink(f.name)
        assert errors == [], f"got {len(errors)} wrong results: {errors[:5]}"
