//! UDP and secure-UDP transport tests — stub. Session 04.
//!
//! Tests to migrate from `end_to_end.rs`:
//! - `udp_client_to_observer_beats_and_stall`  (cfg feature = "udp")
//! - `secure_udp_client_to_observer_beats`     (cfg feature = "secure-udp")
//! - `secure_udp_counter_wrap_continues_under_load` (cfg all(feature = "secure-udp", feature = "test-hooks"))
//! - `secure_udp_fork_safe_under_real_fork`    (cfg all(feature = "secure-udp", target_family = "unix"))
