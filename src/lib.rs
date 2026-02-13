use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

// ── Policy config (shared, read-heavy) ──────────────────────

struct PolicyConfig {
    path: String,
    source: String,
    data_json: Option<String>,
    query: String,
}

static POLICY: RwLock<Option<PolicyConfig>> = RwLock::new(None);
static POLICY_VERSION: AtomicU64 = AtomicU64::new(0);

// ── Thread-local engine cache ───────────────────────────────
// Each thread keeps a ready-to-use Engine.  On evaluate() we only
// call set_input_json + eval_rule — no policy parsing, no cloning.
// The version counter invalidates caches when load_policy() is called.

thread_local! {
    static CACHED_ENGINE: RefCell<Option<(u64, regorus::Engine)>> = const { RefCell::new(None) };
}

fn build_engine(cfg: &PolicyConfig) -> Result<regorus::Engine, String> {
    let mut engine = regorus::Engine::new();
    engine
        .add_policy(cfg.path.clone(), cfg.source.clone())
        .map_err(|e| format!("{e:#}"))?;
    if let Some(ref data) = cfg.data_json {
        engine
            .add_data_json(data)
            .map_err(|e| format!("{e:#}"))?;
    }
    Ok(engine)
}

fn do_eval(input_json: &str) -> Result<String, String> {
    let guard = POLICY.read().unwrap();
    let cfg = guard.as_ref().ok_or("call load_policy() first")?;
    let ver = POLICY_VERSION.load(Ordering::Acquire);
    let query = cfg.query.clone();

    CACHED_ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();

        // Rebuild engine only when policy version changed or first call
        let needs_rebuild = match *slot {
            Some((v, _)) if v == ver => false,
            _ => true,
        };
        if needs_rebuild {
            *slot = Some((ver, build_engine(cfg)?));
        }

        let (_, engine) = slot.as_mut().unwrap();

        engine
            .set_input_json(input_json)
            .map_err(|e| format!("{e:#}"))?;
        let value = engine
            .eval_rule(query)
            .map_err(|e| format!("{e:#}"))?;
        Ok(value.to_string())
    })
}

// ── JSON → Python conversion (no Python json module) ────────

fn json_to_py(py: Python<'_>, v: &serde_json::Value) -> PyResult<PyObject> {
    match v {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok((*b).into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(n.as_f64()
                    .unwrap()
                    .into_pyobject(py)?
                    .into_any()
                    .unbind())
            }
        }
        serde_json::Value::String(s) => Ok(PyString::new(py, s).into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let items: Vec<PyObject> = arr.iter().map(|v| json_to_py(py, v)).collect::<PyResult<_>>()?;
            Ok(PyList::new(py, &items)?.into_any().unbind())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, val) in map {
                dict.set_item(k, json_to_py(py, val)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

/// OPA policy evaluator using regorus.
///
/// Usage:
///     import opa_eval
///     opa_eval.load_policy("policy.rego", query="data.authz.allow")
///     result = opa_eval.evaluate('{"role": "admin"}')
#[pymodule]
fn opa_eval(m: &Bound<'_, PyModule>) -> PyResult<()> {
    /// Load a .rego policy file.
    ///
    /// Args:
    ///     policy_path: Path to a .rego file.
    ///     data_json:   Optional JSON string for external data.
    ///     query:       Rego query to evaluate (default: "data").
    #[pyfn(m)]
    #[pyo3(signature = (policy_path, data_json=None, query=None))]
    fn load_policy(
        policy_path: &str,
        data_json: Option<String>,
        query: Option<String>,
    ) -> PyResult<()> {
        let source = std::fs::read_to_string(policy_path)
            .map_err(|e| PyRuntimeError::new_err(format!("failed to read {policy_path}: {e}")))?;

        // Validate the policy parses
        let mut engine = regorus::Engine::new();
        engine
            .add_policy(policy_path.to_string(), source.clone())
            .map_err(|e| PyRuntimeError::new_err(format!("invalid policy: {e:#}")))?;

        *POLICY.write().unwrap() = Some(PolicyConfig {
            path: policy_path.to_string(),
            source,
            data_json,
            query: query.unwrap_or_else(|| "data".to_string()),
        });
        // Bump version so thread-local caches rebuild
        POLICY_VERSION.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Evaluate the loaded policy with the given input JSON string.
    /// Returns the result as a JSON string.
    /// Thread-safe — each thread caches its own engine instance.
    #[pyfn(m)]
    fn evaluate(input_json: &str) -> PyResult<String> {
        do_eval(input_json).map_err(|e| PyRuntimeError::new_err(e))
    }

    /// Evaluate and return parsed Python object directly.
    /// Converts JSON → Python in Rust (no Python json module overhead).
    #[pyfn(m)]
    fn evaluate_parsed(py: Python<'_>, input_json: &str) -> PyResult<PyObject> {
        let json_str = do_eval(input_json).map_err(|e| PyRuntimeError::new_err(e))?;
        let value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid result JSON: {e}")))?;
        json_to_py(py, &value)
    }

    Ok(())
}
