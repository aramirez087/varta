/**
 * Beat transports — UDP (loopback / LAN), UDS (recovery-eligible same-host),
 * and Secure UDP (ChaCha20-Poly1305).
 *
 * <p>Package-private to the client. Public consumers go through
 * {@link health.varta.Varta} factories.</p>
 */
package health.varta.transport;
