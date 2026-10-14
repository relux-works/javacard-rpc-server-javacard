# v0.6.0 source candidate

This additive minor adds the `authenticated-invalidate` stream workspace cleanup
selector. With persistent storage it generates a runtime in which only an APDU
the owning applet marks authenticated can stage bytes in the persistent
workspace, every refusal, abort, deselect, CLOSE and reset invalidates the
session in transient memory only, and short handler results are staged in the
caller's response span and copied to the workspace only after validation.
Response-stream methods are refused at generation in this mode. See
[the contract, retained-data rules and measurements](AUTHENTICATED-INVALIDATE.md).

The new mode's dispatch entries take a trailing `boolean authenticated`:
`dispatchStreamTo(..., authenticated)`, `processIfStream(apdu, authenticated)`
and the endpoint's `dispatch(..., authenticated)`. The empty selector and
`whole-reply-area` generate the same files as v0.5.0; the 216-row projection and
the measured Auth projection hashes are unchanged. The wire format, status
words other than the new `6982` for an unauthenticated stream APDU, and the
handler signatures are unchanged.

Root runtime metadata is 0.6.0; the Gradle jar is
`build/libs/javacard-rpc-server-javacard-0.6.0.jar` with Implementation-Version
0.6.0. This is a source build coordinate, not a Maven publication. The only
released Go dependency remains pluginapi v0.1.1; the selector string is defined
in this module (`codegen.StreamWorkspaceCleanupAuthenticatedInvalidate`). A
facade release must admit the selector before the CLI can emit it.

Evidence: Go source tests, jCardSim logical-store ledger with positive and
negative instrument controls, fourteen runtime narrowing mutants, one
token-preserving mutant, one generation-time Go mutant, allocation payload and
Classic 3.0.5u4 CAP conversion with off-card verification. Physical-card
behavior, JCRE/native writes and card-wide RAM totals are not claimed.

Independent review, signed tag and release remain release-owner work.
