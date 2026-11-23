# v0.9.0 source candidate

Generated mixed-mode servers can reuse the checked request SHA-256 and hash a
prepared transient response directly. An optional stream workspace lets an
applet stage public uploads in its own RAM and reclaim it after close or abort.
The existing handler fallback, authenticated inputs and short receipts keep
their previous behavior. Request and response wire formats remain compatible.

The root tag pairs backend v0.9.0 with the Java runtime at
`io.jcrpc:javacard-rpc-server-javacard:0.9.0`. Tests cover checked digest
handoff, matching result bytes, transient staging, release, abort and refusal
of persistent memory. See [stream modes](STREAM-MODES.md).
