#![no_main]

use libfuzzer_sys::fuzz_target;
use varta_watch::config::Config;

fuzz_target!(|data: &[u8]| {
    // Null-byte splitting: each segment becomes one argv token.
    let tokens_null: Vec<String> = data
        .split(|&b| b == 0)
        .filter_map(|chunk| String::from_utf8(chunk.to_vec()).ok())
        .collect();
    let _ = Config::from_args(tokens_null);

    // ASCII-whitespace splitting: different token boundaries exercise
    // different parse paths (e.g. "  --threshold-ms   5  ").
    let tokens_ws: Vec<String> = data
        .split(|&b| b.is_ascii_whitespace())
        .filter(|chunk| !chunk.is_empty())
        .filter_map(|chunk| String::from_utf8(chunk.to_vec()).ok())
        .collect();
    let _ = Config::from_args(tokens_ws);
});
