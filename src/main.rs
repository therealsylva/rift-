//! RIFT: evidence analysis, not a vulnerability exploit or CVE confirmation.
use std::{env, fs, process};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    path: String,
    asan: bool,
    ubsan: bool,
    memory_error: bool,
    runtime_error: bool,
    indicators: Vec<String>,
}

fn scan(path: &str) -> Result<Observation, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let data = String::from_utf8_lossy(&bytes);
    let asan = data.contains("ERROR: AddressSanitizer:") || data.contains("SUMMARY: AddressSanitizer:");
    let ubsan = data.contains("runtime error:") || data.contains("UndefinedBehaviorSanitizer");
    let memory_error = data.contains("heap-use-after-free") || data.contains("heap-buffer-overflow")
        || data.contains("stack-buffer-overflow") || data.contains("double-free")
        || data.contains("SEGV on unknown address");
    let runtime_error = data.contains("runtime error:");
    let indicators = ["heap-use-after-free", "heap-buffer-overflow", "stack-buffer-overflow",
        "double-free", "SEGV on unknown address", "runtime error:"]
        .iter().filter(|s| data.contains(**s)).map(|s| s.to_string()).collect();
    Ok(Observation { path: path.into(), asan, ubsan, memory_error, runtime_error, indicators })
}

fn json_string(s: &str) -> String {
    let mut result = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""), '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"), '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"), c if c.is_control() => result.push_str(&format!("\\u{:04x}",c as u32)),
            _ => result.push(c),
        }
    }
    result.push('"'); result
}
fn observation_json(o: &Observation) -> String {
    format!("{{\"path\":{},\"asan_marker\":{},\"ubsan_marker\":{},\"memory_error_marker\":{},\"runtime_error_marker\":{},\"indicators\":[{}]}}",
        json_string(&o.path), o.asan, o.ubsan, o.memory_error, o.runtime_error,
        o.indicators.iter().map(|s| json_string(s)).collect::<Vec<_>>().join(","))
}
fn help() {
    println!("RIFT v0.3 | Runtime Integrity Forensics Toolkit\n\nUSAGE:\n  rift analyze <logfile>\n  rift compare <vulnerable-log> <patched-log>\n  rift --help\n\nOutput is JSON; observations are not proof of a CVE. No network requests are made.");
}
fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, path] if cmd == "analyze" => {
            let o = scan(path)?; println!("{{\"tool\":\"rift\",\"schema\":1,\"evidence_kind\":\"log_observation\",\"observation\":{}}}",observation_json(&o)); Ok(())
        },
        [cmd, before, after] if cmd == "compare" => {
            let b = scan(before)?; let a = scan(after)?;
            let differential = (b.asan || b.ubsan) && !(a.asan || a.ubsan);
            println!("{{\"tool\":\"rift\",\"schema\":1,\"evidence_kind\":\"log_comparison\",\"vulnerable_label\":{},\"patched_label\":{},\"sanitizer_marker_present_only_in_first\":{},\"cve_verified\":false,\"note\":\"File names are user-supplied labels; attribution and build authenticity not verified\"}}",
                observation_json(&b), observation_json(&a), differential);
            Ok(())
        },
        [] => {help(); Ok(())},
        [one] if one == "--help" || one == "-h" || one == "help" => {help(); Ok(())},
        _ => Err("invalid arguments; use rift --help".into())
    }
}
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(e) = run(&args) { eprintln!("RIFT error: {e}"); process::exit(2); }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn escapes_json() { assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\""); }
    #[test] fn empty_log_is_not_diagnostic() {
        let path = std::env::temp_dir().join(format!("rift-empty-{}",std::process::id()));
        fs::write(&path, "ordinary warning").unwrap();
        let obs = scan(path.to_str().unwrap()).unwrap();
        assert!(!obs.asan && !obs.ubsan && !obs.memory_error);
        fs::remove_file(path).unwrap();
    }
    #[test] fn sanitizer_detection() {
        let path = std::env::temp_dir().join(format!("rift-asan-{}",std::process::id()));
        fs::write(&path, "==1==ERROR: AddressSanitizer: heap-use-after-free\n").unwrap();
        let obs = scan(path.to_str().unwrap()).unwrap();
        assert!(obs.asan && obs.memory_error);
        fs::remove_file(path).unwrap();
    }
}
