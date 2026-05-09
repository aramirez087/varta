/**
 * Varta JVM client — health protocol for distributed local agents.
 *
 * <p>Connect to a local {@code varta-watch} observer via UDS, UDP, or
 * Secure UDP, then call {@link health.varta.Varta#beat(health.varta.Status, int)}
 * on a fixed cadence (typically 500 ms). The observer detects stalls,
 * triggers recovery commands, and exports Prometheus metrics.</p>
 *
 * <p>Wire format: VLP v0.2 (32-byte base frame, CRC-32C trailer).
 * Cross-language byte-equality enforced against
 * {@code tools/vlp-test-vectors.json}.</p>
 */
package health.varta;
