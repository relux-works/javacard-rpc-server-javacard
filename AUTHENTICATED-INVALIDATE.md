# Authenticated persistent workspace with transient-only refusal

`stream_workspace = "persistent"` plus
`stream_workspace_cleanup = "authenticated-invalidate"` selects a stream runtime
whose persistent workspace is reachable only from an authenticated APDU and
whose refusals never write it. The selector is additive: the empty selector and
`whole-reply-area` generate byte-identical sources to v0.5.0.

## Contract

| Event | Persistent workspace stores on that APDU | Transient effect |
| --- | ---: | --- |
| Stream APDU with `authenticated == false` (any operation) | 0 | none; refused `6982` before any session read |
| Accepted authenticated WRITE chunk | chunk length, after every shape, order, bound and duplicate check | session advances |
| Byte-identical duplicate of the last chunk | 0 | none |
| Changed duplicate, out-of-order index (the `6A80` retry), bad declaration | 0 | session invalidated |
| CLOSE_WRITE with wrong length or digest | 0 | session invalidated |
| Accepted CLOSE_WRITE (short result) | result length, copied after the handler result was validated | receipt kept for an identical retry |
| CLOSE_WRITE whose response span or caller workspace is not proven RAM (see below) | 0; refused `6985` before the handler or the receipt copy runs | session invalidated |
| Handler failure, or handler length outside the declared result | 0 (output was staged in the admitted RAM/APDU response span) | session invalidated |
| Identical CLOSE_WRITE retry | 0 | receipt returned again |
| Foreign method (WRITE or CLOSE for another method), or invalid caller workspace bounds | 0 | session invalidated; the old CLOSE is refused `6985` and a chunk retry `6A80` |
| ABORT, deselect | 0 | session invalidated |
| Card reset, then any command | 0 | transient state is already empty; no reset sweep |

The generated dispatch entries take one extra trailing argument:

```java
short dispatchStreamTo(byte ins, byte p1, byte p2,
        byte[] request, short requestOffset, short requestLength,
        byte[] response, short responseOffset, short responseCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity,
        boolean authenticated);
boolean processIfStream(APDU apdu, boolean authenticated);   // generated adapter
```

The owning applet computes `authenticated` for the exact APDU (for example from
the GlobalPlatform Secure Channel level after a successful `unwrap`). The runtime
does not decide what authentication means; it only refuses to stage a byte
without it. Ordinary (non-stream) instructions are unaffected.

The unauthenticated `6982` refusal is the only refusal that keeps the live
session: an unauthenticated caller must not be able to cancel an authenticated
upload. Every refused authenticated APDU invalidates the transient session.

## Output admission

On every CLOSE_WRITE, before the handler or the receipt retry copy runs, the
runtime admits the response span and the caller workspace only if each is
proven to be RAM: `JCSystem.isTransient(array) != NOT_A_TRANSIENT_OBJECT`, or
identity with `APDU.getCurrentAPDUBuffer()`. Width checks alone do not prove a
storage class; without this a direct caller could pass an in-bounds persistent
array and a failing handler would write it on a refused APDU. Any other array is
refused `6985` and the session is invalidated, with no handler call.

`APDU.getCurrentAPDUBuffer()` throws `SecurityException` outside the selected
applet's `process()`, for example when a Security Domain forwards STORE DATA
through `Personalization.processData`. There, only a transient array is
proven, and a global buffer the platform does not report as transient is
refused. A consumer that dispatches streams from that context must pass a
transient span; this is a consumer integration obligation, not something the
runtime can prove for it. jCardSim does not enforce that context check.

## Handler contract in this mode

- `input` is the persistent workspace and is read-only. Writing it would be a
  handler-owned persistent store that the runtime cannot prevent.
- `output` is the caller's admitted RAM/APDU response span, preflighted for the exact declared
  width (or 255 B for a variable short result). It may alias the caller
  workspace, as it does when one APDU buffer carries request, response and
  scratch: finish all scratch use, then write the output.
- A handler that fails, or returns a length the runtime rejects, leaves its
  partial output only in that RAM/APDU span. The same holds for scratch
  written to the admitted caller workspace.

## Generation-time refusal

A method with a response stream is refused with an error that names it and its
INS. A streamed result is produced into the persistent workspace during the
CLOSE_WRITE APDU, so a failing handler or a rejected result would leave
persistent writes on a refused APDU. No transient window large enough for a
streamed result exists within a Java Card RAM budget, so the mode does not
offer one. `begin` repeats the refusal at runtime for a direct dispatch call.

The exception is a method with a `stream_mode` (`public-invalidate` or
`chunked`): its result is never stored or held whole. The handler produces it
chunk by chunk into the admitted RAM response span, for the digest at
CLOSE_WRITE and again on every READ_CHUNK. See
[per-method stream modes](STREAM-MODES.md).

## Retained data

After an accepted session the workspace keeps the request bytes and the short
result receipt. Nothing erases them: refusal, abort, deselect and reset only
clear the transient scalars, digest scratch and handler slot. Retained bytes
are therefore only those an authenticated APDU accepted, and this mode is meant
for public data. Do not stream secrets through it.

Access after invalidation: no operation reads the workspace without a live
transient state. READ is absent (no response streams). A CLOSE_WRITE retry
returns the receipt only in the live `SHORT_CLOSED` state with the exact length
and digest; after abort, deselect or reset it is refused `6985`. The duplicate
check reads only the last chunk of the live session. A new session overwrites
only the spans it accepts, and its handler sees only `[0, inputLength)`, all of
which were written in that session. A power loss during an accepted copy can
leave a mix of old and new public bytes with no live handle; no later refusal
clears them. No erasure is claimed.

## Measurements

Generated example `AuthShape` on jCardSim 3.0.5.9-relux.1 through
`Simulator.transmitCommand -> Applet.process`, on both the generated adapter and
an Auth-shaped direct `dispatchStreamTo` over one APDU buffer, both lifecycle
choices. The ledger counts every array element store in generated sources and
fixture handlers, classified by array identity (`JCSystem.isTransient`, APDU
buffer). Same-value stores count. JCRE transaction journaling, native crypto
state and physical EEPROM endurance are outside this count.

| Workload | Logical persistent stores |
| --- | ---: |
| 197 B request (192 + 5) + 73 B accepted result | 270 B |
| 2048 B request (11 chunks) + 73 B accepted result | 2121 B |
| 40 B request + 36 B accepted result | 76 B |
| Every refused APDU listed above, ABORT, deselect, reset, retries | 0 B each |
| CLOSE with a persistent response or caller workspace (handler set to fail, and to succeed) | 0 B, handler not called |

Reachable generated array payload for the request-only BSim Auth fixture
(the Auth IDL without its two response streams), clear-on-reset:

| Selector | Skeleton-reachable transient | Persistent (workspace + tables) | Generated adapter I/O (if constructed) |
| --- | ---: | ---: | ---: |
| `whole-reply-area` | 75 B | 2132 B | 255 B transient |
| `authenticated-invalidate` | 72 B | 2132 B | 255 B transient |

The 3 B saving is the dropped reset marker and dirty frontier. Object headers,
provider/JCRE arrays and reference widths are excluded. This is a generator
payload, not a whole-card RAM figure; a card total must add every applet's own
measured reserve.

## Evidence and limits

Tests (`codegen/gen_java_authenticated_test.go`): selector refusals with a
positive control; named response-stream refusal of the real Auth fixture;
source contract; the simulator scenario above; ledger controls (a planted
same-value persistent store, also through an alias, fails the zero gate by name;
a planted transient store passes); twenty runtime narrowing mutants (seven
gate weakenings; one same-value persistent store planted on exactly one
refusal or invalidation path each for bad CLOSE digest, ABORT, foreign method,
handler failure, deselect, out-of-order retry and oversized declaration; four
output-admission narrowings that admit a persistent span only for the sign
method, only as caller workspace, only for a 255 B array, or only on the
receipt retry; two foreign-refusal narrowings that keep the handle only for
the sign method, on WRITE and on CLOSE); two review regression witnesses
(`TestReviewerPersistentResponseRefusal`, `TestReviewerForeignMethodInvalidates`); one
token-preserving mutant and one generation-time Go mutant, each killed by a
named assertion; allocation payload; Classic 3.0.5u4 CAP conversion with
off-card verification for both lifecycle choices.

Not established here: physical-card behavior, JCRE or native-key writes, a
card-wide RAM total, or a downstream consumer's handlers. Consumers prove their
own handlers do not write `input` or other persistent state before refusal.
