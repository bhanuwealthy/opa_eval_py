import json
import os
import tempfile

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
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(opa_eval.evaluate, inp)


def test_evaluate_simple_deny(benchmark):
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "viewer"})
    benchmark(opa_eval.evaluate, inp)


def test_evaluate_parsed(benchmark):
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(opa_eval.evaluate_parsed, inp)


# ── With external data ────────────────────────────────────

def test_evaluate_with_data(benchmark):
    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
        f.write(DATA_POLICY)
        f.flush()
        opa_eval.load_policy(
            f.name,
            data_json=json.dumps({"roles": ROLES}),
            query="data.rbac.allow",
        )
    inp = json.dumps({"user": "user0"})
    benchmark(opa_eval.evaluate, inp)
    os.unlink(f.name)


# ── Input size scaling ────────────────────────────────────

def test_evaluate_small_input(benchmark):
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    benchmark(opa_eval.evaluate, inp)


def test_evaluate_large_input(benchmark):
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin", "extra": {f"key{i}": f"val{i}" for i in range(100)}})
    benchmark(opa_eval.evaluate, inp)


# ── load_policy cost ──────────────────────────────────────

def test_load_policy(benchmark):
    benchmark(opa_eval.load_policy, POLICY_PATH, None, "data.authz.allow")


# ── Concurrent load tests ────────────────────────────────

from concurrent.futures import ThreadPoolExecutor
import time
import threading


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


class TestConcurrentThroughput:
    """Sustained multi-thread throughput tests."""

    def test_throughput_1_thread(self):
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: opa_eval.evaluate(inp), workers=1)
        print(f"\n  1 thread: {ops:,.0f} ops/sec")
        assert ops > 50_000

    def test_throughput_4_threads(self):
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: opa_eval.evaluate(inp), workers=4)
        print(f"\n  4 threads: {ops:,.0f} ops/sec")
        assert ops > 100_000

    def test_throughput_8_threads(self):
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: opa_eval.evaluate(inp), workers=8)
        print(f"\n  8 threads: {ops:,.0f} ops/sec")
        assert ops > 100_000

    def test_throughput_parsed_4_threads(self):
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        ops = _throughput(lambda: opa_eval.evaluate_parsed(inp), workers=4)
        print(f"\n  4 threads (parsed): {ops:,.0f} ops/sec")
        assert ops > 80_000

    def test_throughput_with_data_4_threads(self):
        with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
            f.write(DATA_POLICY)
            f.flush()
            opa_eval.load_policy(
                f.name,
                data_json=json.dumps({"roles": ROLES}),
                query="data.rbac.allow",
            )
        inp = json.dumps({"user": "user0"})
        ops = _throughput(lambda: opa_eval.evaluate(inp), workers=4)
        print(f"\n  4 threads (data): {ops:,.0f} ops/sec")
        os.unlink(f.name)
        assert ops > 80_000


class TestConcurrentCorrectness:
    """Verify results stay correct under heavy concurrent load."""

    def test_mixed_inputs_correctness(self):
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
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
                result = opa_eval.evaluate_parsed(inp)
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

    def test_reload_under_load(self):
        """Reload policy while evaluations are running — no crashes."""
        opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
        inp = json.dumps({"role": "admin"})
        stop = threading.Event()
        eval_count = [0]
        reload_count = [0]

        def evaluator():
            c = 0
            while not stop.is_set():
                try:
                    opa_eval.evaluate(inp)
                    c += 1
                except Exception:
                    pass  # transient during reload is acceptable
            eval_count[0] += c

        def reloader():
            c = 0
            while not stop.is_set():
                opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
                c += 1
                time.sleep(0.01)
            reload_count[0] = c

        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(evaluator) for _ in range(4)]
            futs.append(pool.submit(reloader))
            time.sleep(2.0)
            stop.set()
            for f in futs:
                f.result()

        print(f"\n  evals: {eval_count[0]:,}  reloads: {reload_count[0]}")
        assert eval_count[0] > 1000
