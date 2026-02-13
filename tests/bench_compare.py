"""Benchmark: opa_eval (Rust/regorus) vs OPA REST API vs OPA CLI."""

import atexit
import json
import os
import signal
import subprocess
import tempfile
import time

import plotly.graph_objects as go
import requests

import opa_eval

POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.rego")
ITERATIONS = 500
OPA_PORT = 18181
OPA_BASE = f"http://localhost:{OPA_PORT}"

DATA_POLICY = """\
package rbac

import rego.v1

default allow := false

allow if {
    role := data.roles[input.user]
    role == "admin"
}
"""

ROLES_DATA = {"roles": {f"user{i}": ("admin" if i % 10 == 0 else "viewer") for i in range(100)}}


# ── OPA server lifecycle ─────────────────────────────────────

_opa_proc = None


def start_opa_server(*policy_files):
    """Start OPA in server mode, loading the given policy files."""
    global _opa_proc
    stop_opa_server()
    cmd = ["opa", "run", "-s", "--addr", f":{OPA_PORT}", "--log-level", "error", *policy_files]
    _opa_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait until healthy
    for _ in range(40):
        try:
            r = requests.get(f"{OPA_BASE}/health", timeout=0.5)
            if r.status_code == 200:
                return
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    raise RuntimeError("OPA server failed to start")


def stop_opa_server():
    global _opa_proc
    if _opa_proc is not None:
        _opa_proc.send_signal(signal.SIGTERM)
        _opa_proc.wait(timeout=5)
        _opa_proc = None


atexit.register(stop_opa_server)


def opa_rest_put_data(data: dict):
    """PUT external data into the running OPA server."""
    r = requests.put(f"{OPA_BASE}/v1/data", json=data, timeout=5)
    r.raise_for_status()


def opa_rest_eval(path: str, input_data: dict) -> dict:
    """POST to OPA REST API to evaluate a policy rule."""
    r = requests.post(f"{OPA_BASE}/v1/data/{path}", json={"input": input_data}, timeout=5)
    r.raise_for_status()
    return r.json()


# ── Benchmark functions ──────────────────────────────────────

# --- Rust (in-process) -------

def bench_rust_simple(iterations: int) -> float:
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin"})
    start = time.perf_counter()
    for _ in range(iterations):
        opa_eval.evaluate(inp)
    return time.perf_counter() - start


def bench_rust_deny(iterations: int) -> float:
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "viewer"})
    start = time.perf_counter()
    for _ in range(iterations):
        opa_eval.evaluate(inp)
    return time.perf_counter() - start


def bench_rust_with_data(iterations: int) -> float:
    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
        f.write(DATA_POLICY)
        f.flush()
        opa_eval.load_policy(f.name, data_json=json.dumps(ROLES_DATA), query="data.rbac.allow")
    inp = json.dumps({"user": "user0"})
    start = time.perf_counter()
    for _ in range(iterations):
        opa_eval.evaluate(inp)
    elapsed = time.perf_counter() - start
    os.unlink(f.name)
    return elapsed


def bench_rust_large_input(iterations: int) -> float:
    opa_eval.load_policy(POLICY_PATH, query="data.authz.allow")
    inp = json.dumps({"role": "admin", "extra": {f"key{i}": f"val{i}" for i in range(200)}})
    start = time.perf_counter()
    for _ in range(iterations):
        opa_eval.evaluate(inp)
    return time.perf_counter() - start


# --- OPA REST API -------

def bench_rest_simple(iterations: int) -> float:
    start_opa_server(POLICY_PATH)
    payload = {"input": {"role": "admin"}}
    url = f"{OPA_BASE}/v1/data/authz/allow"
    start = time.perf_counter()
    for _ in range(iterations):
        requests.post(url, json=payload)
    elapsed = time.perf_counter() - start
    stop_opa_server()
    return elapsed


def bench_rest_deny(iterations: int) -> float:
    start_opa_server(POLICY_PATH)
    payload = {"input": {"role": "viewer"}}
    url = f"{OPA_BASE}/v1/data/authz/allow"
    start = time.perf_counter()
    for _ in range(iterations):
        requests.post(url, json=payload)
    elapsed = time.perf_counter() - start
    stop_opa_server()
    return elapsed


def bench_rest_with_data(iterations: int) -> float:
    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as f:
        f.write(DATA_POLICY)
        f.flush()
        policy_file = f.name
    start_opa_server(policy_file)
    opa_rest_put_data(ROLES_DATA)
    payload = {"input": {"user": "user0"}}
    url = f"{OPA_BASE}/v1/data/rbac/allow"
    start = time.perf_counter()
    for _ in range(iterations):
        requests.post(url, json=payload)
    elapsed = time.perf_counter() - start
    stop_opa_server()
    os.unlink(policy_file)
    return elapsed


def bench_rest_large_input(iterations: int) -> float:
    start_opa_server(POLICY_PATH)
    payload = {"input": {"role": "admin", "extra": {f"key{i}": f"val{i}" for i in range(200)}}}
    url = f"{OPA_BASE}/v1/data/authz/allow"
    start = time.perf_counter()
    for _ in range(iterations):
        requests.post(url, json=payload)
    elapsed = time.perf_counter() - start
    stop_opa_server()
    return elapsed


# --- OPA CLI (subprocess) -------

def bench_cli_simple(iterations: int) -> float:
    inp = json.dumps({"role": "admin"})
    start = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(
            ["opa", "eval", "-d", POLICY_PATH, "-i", "/dev/stdin", "data.authz.allow"],
            input=inp, capture_output=True, text=True, check=True,
        )
    return time.perf_counter() - start


def bench_cli_deny(iterations: int) -> float:
    inp = json.dumps({"role": "viewer"})
    start = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(
            ["opa", "eval", "-d", POLICY_PATH, "-i", "/dev/stdin", "data.authz.allow"],
            input=inp, capture_output=True, text=True, check=True,
        )
    return time.perf_counter() - start


def bench_cli_with_data(iterations: int) -> float:
    with tempfile.NamedTemporaryFile(suffix=".rego", mode="w", delete=False) as pf:
        pf.write(DATA_POLICY)
        pf.flush()
        policy_file = pf.name
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as df:
        json.dump(ROLES_DATA, df)
        df.flush()
        data_file = df.name
    inp = json.dumps({"user": "user0"})
    start = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(
            ["opa", "eval", "-d", policy_file, "--data", data_file, "-i", "/dev/stdin", "data.rbac.allow"],
            input=inp, capture_output=True, text=True, check=True,
        )
    elapsed = time.perf_counter() - start
    os.unlink(policy_file)
    os.unlink(data_file)
    return elapsed


def bench_cli_large_input(iterations: int) -> float:
    inp = json.dumps({"role": "admin", "extra": {f"key{i}": f"val{i}" for i in range(200)}})
    start = time.perf_counter()
    for _ in range(iterations):
        subprocess.run(
            ["opa", "eval", "-d", POLICY_PATH, "-i", "/dev/stdin", "data.authz.allow"],
            input=inp, capture_output=True, text=True, check=True,
        )
    return time.perf_counter() - start


# ── Scenario registry ────────────────────────────────────────

SCENARIOS = [
    #  (label,           rust_fn,                rest_fn,              cli_fn)
    ("Simple allow",     bench_rust_simple,      bench_rest_simple,    bench_cli_simple),
    ("Deny path",        bench_rust_deny,        bench_rest_deny,      bench_cli_deny),
    ("With ext data",    bench_rust_with_data,   bench_rest_with_data, bench_cli_with_data),
    ("Large input",      bench_rust_large_input, bench_rest_large_input, bench_cli_large_input),
]


# ── Run & chart ──────────────────────────────────────────────

def main():
    iters = ITERATIONS

    print(f"Benchmarking  ({iters} iterations each)\n")

    results = []
    for label, rust_fn, rest_fn, cli_fn in SCENARIOS:
        print(f"  {label}:", flush=True)

        t_rust = rust_fn(iters)
        us_rust = (t_rust / iters) * 1_000_000
        print(f"    Rust/PyO3   {us_rust:>10.1f} us/op", flush=True)

        t_rest = rest_fn(iters)
        us_rest = (t_rest / iters) * 1_000_000
        spd_rest = us_rest / us_rust
        print(f"    OPA REST    {us_rest:>10.0f} us/op  ({spd_rest:>6.0f}x vs Rust)", flush=True)

        t_cli = cli_fn(iters)
        us_cli = (t_cli / iters) * 1_000_000
        spd_cli = us_cli / us_rust
        print(f"    OPA CLI     {us_cli:>10.0f} us/op  ({spd_cli:>6.0f}x vs Rust)", flush=True)

        results.append((label, us_rust, us_rest, us_cli))

    # ── Summary table ────────────────────────────────────────
    print("\n" + "=" * 82)
    print(f"{'Scenario':<16} {'Rust (us)':>10} {'REST (us)':>11} {'CLI (us)':>11} {'REST/Rust':>10} {'CLI/Rust':>10}")
    print("-" * 82)
    for label, r, rest, cli in results:
        print(f"{label:<16} {r:>10.1f} {rest:>11.0f} {cli:>11.0f} {rest/r:>9.0f}x {cli/r:>9.0f}x")
    print("=" * 82)

    # ── Build chart data ──────────────────────────────────────
    labels = [r[0] for r in results]
    rust_us = [r[1] for r in results]
    rest_us = [r[2] for r in results]
    cli_us  = [r[3] for r in results]

    fig = go.Figure()

    # --- OPA CLI bars (slowest — red) ---
    cli_text = [
        f"<b>{v:,.0f}</b> us  ·  {v/r:.0f}x slower"
        for v, r in zip(cli_us, rust_us)
    ]
    fig.add_trace(go.Bar(
        y=labels, x=cli_us,
        orientation="h",
        name="OPA CLI (subprocess)",
        marker=dict(
            color="rgba(255, 75, 75, 0.85)",
            line=dict(color="rgba(255, 120, 120, 1)", width=1),
        ),
        text=cli_text,
        textposition="inside",
        insidetextanchor="end",
        textfont=dict(color="white", size=13),
    ))

    # --- OPA REST bars (middle — amber) ---
    rest_text = [
        f"<b>{v:,.0f}</b> us  ·  {v/r:.0f}x slower"
        for v, r in zip(rest_us, rust_us)
    ]
    fig.add_trace(go.Bar(
        y=labels, x=rest_us,
        orientation="h",
        name="OPA REST API (HTTP)",
        marker=dict(
            color="rgba(255, 183, 50, 0.85)",
            line=dict(color="rgba(255, 210, 100, 1)", width=1),
        ),
        text=rest_text,
        textposition="inside",
        insidetextanchor="end",
        textfont=dict(color="#1a1a2e", size=13, family="monospace"),
    ))

    # --- Rust/PyO3 bars (fastest — electric green with glow) ---
    fig.add_trace(go.Bar(
        y=labels, x=rust_us,
        orientation="h",
        name="opa_eval  (Rust / PyO3)",
        marker=dict(
            color="rgba(0, 230, 118, 0.9)",
            line=dict(color="rgba(100, 255, 180, 1)", width=2),
        ),
        text=[f"  <b>{v:.0f} us</b>" for v in rust_us],
        textposition="outside",
        textfont=dict(color="#00e676", size=14, family="monospace"),
    ))

    # --- Layout: dark theme, log scale ---
    import math
    max_cli = max(cli_us)
    max_x = max_cli * 2.5  # room for labels
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0d1117",
        plot_bgcolor="#161b22",
        title=dict(
            text=(
                "<b style='color:#00e676; font-size:24px'>opa_eval</b>"
                "<b style='font-size:20px'>  (Rust/regorus)  vs  OPA REST  vs  OPA CLI</b><br>"
                "<span style='font-size:14px; color:#8b949e'>"
                "Per-evaluation latency (us)  |  Log scale  |  Lower is better  |  "
                "Nx = times slower than Rust</span>"
            ),
            font=dict(size=20, color="#e6edf3"),
            x=0.5,
        ),
        xaxis=dict(
            title=dict(
                text="Microseconds per evaluation  (log scale — each gridline is 10x)",
                font=dict(size=13, color="#8b949e"),
            ),
            type="log",
            range=[0.7, math.log(max_x, 56)],
            gridcolor="rgba(139,148,158,0.12)",
            zerolinecolor="rgba(139,148,158,0.12)",
            tickfont=dict(size=12, color="#8b949e"),
            dtick=1,
        ),
        yaxis=dict(
            tickfont=dict(size=14, color="#e6edf3"),
            autorange="reversed",
        ),
        barmode="group",
        bargap=0.30,
        bargroupgap=0.05,
        legend=dict(
            orientation="h",
            yanchor="bottom", y=1.02,
            xanchor="center", x=0.5,
            font=dict(size=13, color="#e6edf3"),
            bgcolor="rgba(0,0,0,0)",
        ),
        margin=dict(l=130, r=80, t=120, b=70),
        height=560,
        width=1200,
    )

    chart_path = os.path.join(os.path.dirname(__file__), "bench_chart.png")
    html_path  = os.path.join(os.path.dirname(__file__), "bench_chart.html")
    fig.write_image(chart_path, scale=2)
    fig.write_html(html_path)
    print(f"\nChart saved to {chart_path}")
    print(f"Interactive chart saved to {html_path}")
    fig.show()


if __name__ == "__main__":
    main()
