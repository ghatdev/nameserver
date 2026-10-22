use std::sync::atomic::{AtomicBool, Ordering};

static JSON_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_json_mode(enabled: bool) {
    JSON_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_json() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// If --json mode, print the value as JSON and return true.
/// Otherwise return false so the caller can do human-friendly output.
pub fn maybe_json(data: &serde_json::Value) -> bool {
    if is_json() {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        true
    } else {
        false
    }
}
