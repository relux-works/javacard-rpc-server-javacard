# v0.8.0 source candidate

This release adds `abortPublicStreams(reason)` to mixed-mode generated
skeletons and `abortPublic(reason)` to their endpoint/runtime. An applet can
invalidate public uploads, pending results and cached short receipts when
external authority changes. The operation preserves authenticated issuer
streams, performs no handler call and clears only transient runtime state.
The applet remains responsible for its own transient handler state. Full
`abortStreams(reason)` continues to clear every stream.

Authenticated-only generation retains its existing surface. The wire protocol
and declared method modes are unchanged. The public short-receipt fixture now
implements its callback in both the simulator and Classic converter applets.

The root tag versions the Go backend and Java runtime together as 0.8.0;
coordinates are `io.jcrpc:javacard-rpc-server-javacard:0.8.0`. Source review,
ordinary checks, simulator controls and Classic CAP conversion are release
requirements; this candidate note is not a completed release verdict.

For reset-scoped streams the digest must support `externalAccess=true`, since
an associated Security Domain may forward data while another applet is selected.
Host qualification uses `works.relux:jcardsim:3.0.5.9-relux.4`, which supports
that API and logical-channel routing. The complete suite also checks that an
unopened channel is rejected by the simulator before AppletBase dispatch; the
older relux.2 and upstream 3.0.5.9 simulators lack that routing behavior and cannot
qualify this control. Upstream `com.klinec:jcardsim:3.0.5.9` throws `CryptoException` during
reset-scoped fixture construction at `MessageDigest.getInstance`; deselect-scoped
tests and public-invalidation controls run there. This is a simulator limitation,
not a reason to weaken the generated digest's required access semantics.
Host/converter results do not establish physical-card or COS qualification.
