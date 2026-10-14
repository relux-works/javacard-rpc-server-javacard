# v0.6.0 source candidate

This additive minor adds the `authenticated-invalidate` stream workspace cleanup
selector. With persistent storage it generates a runtime in which only an APDU
the owning applet marks authenticated can stage bytes in the persistent
workspace, every refusal, abort, deselect, CLOSE and reset invalidates the
session in transient memory only, and short handler results are staged in the
caller's response span and copied to the workspace only after validation. A
CLOSE_WRITE is admitted only when its response span and caller workspace are
proven RAM (a transient array or the current APDU buffer); otherwise it is
refused `6985` before the handler runs. Every refused authenticated APDU,
including a foreign method, invalidates the session; only the unauthenticated
`6982` refusal leaves it intact.
Response-stream methods are refused at generation in this mode. See
[the contract, retained-data rules and measurements](AUTHENTICATED-INVALIDATE.md).

Inside that runtime a per-method `Method.StreamMode` (pluginapi v0.1.2) selects
two more contracts; see [per-method stream modes](STREAM-MODES.md):

- `public-invalidate` admits unauthenticated APDUs. Accepted chunks are staged
  in the persistent workspace and every refused APDU writes nothing persistent
  and invalidates the stream. A streamed result is never stored: the handler
  prepares it at CLOSE_WRITE and produces each chunk into the admitted RAM
  response span, once for the result digest and again on every READ_CHUNK.
- `chunked` delivers each accepted chunk from the caller's request span to the
  handler and a running digest, so no APDU of the method, accepted or refused,
  writes persistent memory. A short result goes into the admitted RAM span; a
  streamed result is produced into it on every read from handler-held state and
  read-only records. Repeated chunks and CLOSE retries after success are
  refused because nothing is staged.

An unauthenticated APDU of any method cannot cancel or join a live
authenticated upload. Schemas without a mode generate the same files as the
reviewed `authenticated-invalidate` candidate.

The new mode's dispatch entries take a trailing `boolean authenticated`:
`dispatchStreamTo(..., authenticated)`, `processIfStream(apdu, authenticated)`
and the endpoint's `dispatch(..., authenticated)`. The empty selector and
`whole-reply-area` generate the same files as v0.5.0; the 216-row projection and
the measured Auth projection hashes are unchanged. The wire format, status
words other than the new `6982` for an unauthenticated stream APDU, and the
handler signatures are unchanged.

Root runtime metadata is 0.6.0; the Gradle jar is
`build/libs/javacard-rpc-server-javacard-0.6.0.jar` with Implementation-Version
0.6.0. This is a source build coordinate, not a Maven publication. The only Go
dependency is pluginapi v0.1.2, which adds `Method.StreamMode`; it must be
tagged before this release, and until then the candidate requires the reviewed
pluginapi commit as a pseudo-version. The cleanup selector string is defined in
this module (`codegen.StreamWorkspaceCleanupAuthenticatedInvalidate`) and the
mode names are re-exported (`codegen.StreamModePublicInvalidate`,
`codegen.StreamModeChunked`). A facade release must admit the selector and the
modes before the CLI can emit them.

Evidence: Go source tests, jCardSim logical-store ledger with positive and
negative instrument controls, twenty runtime narrowing mutants, two review
regression witnesses, one
token-preserving mutant, one generation-time Go mutant, allocation payload and
Classic 3.0.5u4 CAP conversion with off-card verification. The modes add their
own jCardSim scenario with real ECDSA over chunked transcripts, ledger controls
on refusal, chunked-success and producer-read paths, thirty-one behavioral
narrowing mutants, one token-preserving mutant, two generation-time Go mutants,
the allocation payload of the full Auth fixture and CAP conversion. Physical-card
behavior, JCRE/native writes (including Signature and MessageDigest state) and
card-wide RAM totals are not claimed.

Independent review, signed tag and release remain release-owner work.
