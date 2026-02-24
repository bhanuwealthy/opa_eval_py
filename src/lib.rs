use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use std::sync::Mutex;

// ── JSON → Python conversion (no Python json module) ────────────────────────

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
            let items: Vec<PyObject> = arr
                .iter()
                .map(|v| json_to_py(py, v))
                .collect::<PyResult<_>>()?;
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

// ── OpaEval pyclass ──────────────────────────────────────────────────────────

/// An OPA policy evaluator backed by the regorus engine.
///
/// Each instance is independent: it loads its own `.rego` file, optional
/// external data, and remembers the Rego query to run on every call to
/// `evaluate` / `evaluate_parsed`.
///
/// Example
/// -------
/// >>> import opa_eval
/// >>> authz = opa_eval.OpaEval("authz.rego", query="data.authz.allow")
/// >>> result = authz.evaluate('{"role": "admin"}')
/// >>> parsed = authz.evaluate_parsed('{"role": "admin"}')
#[pyclass]
struct OpaEval {
    /// The compiled regorus engine, wrapped in a `Mutex` for `Send + Sync`.
    /// `PyO3` requires `#[pyclass]` types to be `Send`; `Mutex<Engine>` satisfies
    /// that as long as `regorus::Engine: Send` (verified at compile time).
    engine: Mutex<regorus::Engine>,
    /// Rego query evaluated on every call (e.g. `"data.authz.allow"`).
    query: String,
}

#[pymethods]
impl OpaEval {
    /// Create a new `OpaEval` instance.
    ///
    /// Parameters
    /// ----------
    /// `policy_path` : str
    ///     Path to a `.rego` source file.
    /// `data_json` : str, optional
    ///     JSON string providing external data (`data` document).
    /// query : str, optional
    ///     Rego rule to evaluate on each call.  Defaults to `"data"`.
    #[new]
    #[pyo3(signature = (policy_path, data_json=None, query=None))]
    fn new(
        policy_path: &str,
        data_json: Option<&str>,
        query: Option<String>,
    ) -> PyResult<Self> {
        let source = std::fs::read_to_string(policy_path).map_err(|e| {
            PyRuntimeError::new_err(format!("failed to read {policy_path}: {e}"))
        })?;

        let mut engine = regorus::Engine::new();
        engine
            .add_policy(policy_path.to_string(), source)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid policy: {e:#}")))?;

        if let Some(data) = data_json {
            engine
                .add_data_json(data)
                .map_err(|e| PyRuntimeError::new_err(format!("invalid data JSON: {e:#}")))?;
        }

        Ok(Self {
            engine: Mutex::new(engine),
            query: query.unwrap_or_else(|| "data".to_string()),
        })
    }

    /// Evaluate the policy with the given input JSON and return a JSON string.
    ///
    /// Parameters
    /// ----------
    /// `input_json` : str
    ///     JSON-encoded input document.
    ///
    /// Returns
    /// -------
    /// str
    ///     The evaluation result serialised as a JSON string.
    fn evaluate(&self, input_json: &str) -> PyResult<String> {
        self.do_eval(input_json)
    }

    /// Evaluate the policy and return the result as a native Python object.
    ///
    /// Converts JSON to Python entirely in Rust, avoiding any Python
    /// `json.loads` overhead.
    ///
    /// Parameters
    /// ----------
    /// `input_json` : str
    ///     JSON-encoded input document.
    ///
    /// Returns
    /// -------
    /// object
    ///     The evaluation result as a Python `bool`, `int`, `float`,
    ///     `str`, `list`, `dict`, or `None`.
    fn evaluate_parsed(&self, py: Python<'_>, input_json: &str) -> PyResult<PyObject> {
        let json_str = self.do_eval(input_json)?;
        let value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid result JSON: {e}")))?;
        json_to_py(py, &value)
    }
}

impl OpaEval {
    /// Inner evaluation helper: locks the engine, sets input, runs the query.
    fn do_eval(&self, input_json: &str) -> PyResult<String> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("engine lock poisoned: {e}")))?;

        engine
            .set_input_json(input_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid input JSON: {e:#}")))?;

        let value = engine
            .eval_rule(self.query.clone())
            .map_err(|e| PyRuntimeError::new_err(format!("eval error: {e:#}")))?;

        Ok(value.to_string())
    }
}

// ── Module registration ──────────────────────────────────────────────────────

#[pymodule]
fn opa_eval(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OpaEval>()?;
    Ok(())
}
