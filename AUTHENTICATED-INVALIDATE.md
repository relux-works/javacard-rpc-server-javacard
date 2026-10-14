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
| Handler failure, or handler length outside the declared result | 0 (output was staged in the caller's response span) | session invalidated |
| Identical CLOSE_WRITE retry | 0 | receipt returned again |
| Foreign method or invalid caller workspace | 0 | live session kept |
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

## Handler contract in this mode

- `input` is the persistent workspace and is read-only. Writing it would be a
  handler-owned persistent store that the runtime cannot prevent.
- `output` is the caller's response span, preflighted for the exact declared
  width (or 255 B for a variable short result). It may alias the caller
  workspace, as it does when one APDU buffer carries request, response and
  scratch: finish all scratch use, then write the output.
- A handler that fails, or returns a length the runtime rejects, leaves its
  partial output only in the response span.

## Generation-time refusal

A method with a response stream is refused with an error that names it and its
INS. A streamed result is produced into the persistent workspace during the
CLOSE_WRITE APDU, so a failing handler or a rejected result would leave
persistent writes on a refused APDU. No transient window large enough for a
streamed result exists within a Java Card RAM budget, so the mode does not
offer one. `begin` repeats the refusal at runtime for a direct dispatch call.

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
a planted transient store passes); seven runtime narrowing mutants, one
token-preserving mutant and one generation-time Go mutant, each killed by a
named assertion; allocation payload; Classic 3.0.5u4 CAP conversion with
off-card verification for both lifecycle choices.

Not established here: physical-card behavior, JCRE or native-key writes, a
card-wide RAM total, or a downstream consumer's handlers. Consumers prove their
own handlers do not write `input` or other persistent state before refusal.
