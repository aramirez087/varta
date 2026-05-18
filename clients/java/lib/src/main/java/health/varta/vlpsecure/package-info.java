/**
 * VLP-Secure cryptographic primitives — HKDF-SHA256 key derivation and
 * ChaCha20-Poly1305 AEAD seal/open. Normative spec:
 * {@code book/src/spec/vlp-secure.md}.
 *
 * <p>All primitives sourced from the standard JCE
 * ({@code Mac.HmacSHA256}, {@code Cipher.ChaCha20-Poly1305}). No
 * third-party cryptography dependency.</p>
 */
package health.varta.vlpsecure;
