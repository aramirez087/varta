/**
 * Panic / shutdown handlers — emit a {@code CRITICAL} + {@code NONCE_TERMINAL}
 * beat before the process exits.
 *
 * <p>Two installer flavours:</p>
 * <ul>
 *   <li>{@link health.varta.panic.SignalHandler#installShutdownHookUds(java.nio.file.Path)}
 *       — universal (all OSes), uses {@link Runtime#addShutdownHook}.</li>
 *   <li>{@link health.varta.panic.SignalHandler#installSignalHandlerUds(java.nio.file.Path)}
 *       — POSIX-only, traps SIGTERM/SIGINT/SIGQUIT/SIGHUP via
 *       {@code sun.misc.Signal}.</li>
 * </ul>
 *
 * <p>Handlers fail closed: if the transport cannot be pre-bound, or (for
 * Secure UDP) the OS RNG is unavailable, install throws
 * {@link health.varta.PanicInstallException}.</p>
 */
package health.varta.panic;
