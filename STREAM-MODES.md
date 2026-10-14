# Per-method stream modes

`Method.StreamMode` (IDL `stream_mode`, pluginapi v0.1.2) selects a stream
contract per method inside the `authenticated-invalidate` runtime. A method
without a mode keeps the [authenticated contract](AUTHENTICATED-INVALIDATE.md).
Schemas with no mode generate exactly the same files as before; that is
pinned by `TestStreamModesKeepAuthenticatedOutput`.

| Mode | Authentication | Request bytes | Result | Persistent writes |
| --- | --- | --- | --- | --- |
| none (authenticated) | required per APDU | staged in the persistent workspace | short, staged in the caller's RAM span, receipt copied after validation | accepted chunks and the accepted receipt only |
| `public-invalidate` | not required | staged in the persistent workspace | short as above, or streamed: produced into RAM on every read, never stored | accepted chunks (and a short receipt) only |
| `chunked` | not required | never staged: each chunk goes to the handler and a running digest | short, written by the handler into the caller's RAM span, or streamed: produced into RAM on every read from handler-held state and read-only records, never stored | none, on any APDU |

REV4 Auth assignment (owner decision; Auth adoption is downstream work):
provisioning INS 0x10 is `public-invalidate`; signatures INS 0x20/0x30/0x40
and admission INS 0x70 are `chunked`; issuer methods keep no mode.

## Selection and refusals

A mode requires `stream_workspace = "persistent"`,
`stream_workspace_cleanup = "authenticated-invalidate"` and a request stream.
A method without a mode and with a response stream is refused as before. Unknown values, a mode on an
ordinary method or under another cleanup selector are refused by name, and no
file is returned. The facade repeats these checks before generation.

The generated `STREAM_MODES` table gives each streamed method its mode and the
skeleton passes it to `dispatch(..., methodMode, ...)`. The runtime rechecks the
combination in `begin` and refuses an unknown mode, a streamed result of a
method without a mode and a method without a request stream with `6A84` before
any effect.

## Authority

- A method without a mode stages nothing before authentication: an
  unauthenticated APDU is refused `6982` before any session or persistent
  effect, as in the authenticated contract.
- An unauthenticated APDU of **any** method is refused `6982`, without
  touching the session, while an authenticated upload is live (`WRITING`). A
  public caller can neither cancel nor join an issuer upload.
- A finished issuer session (receipt kept for a retry) does not block public
  callers: a public WRITE starts a new session and the receipt handle is
  dropped.
- Every other refused APDU invalidates the live session in transient memory
  only. That includes foreign methods: an authenticated foreign APDU kills a
  public or chunked session, and any foreign APDU kills a public one.

## `public-invalidate`

| Event | Persistent stores on that APDU | Transient effect |
| --- | ---: | --- |
| Accepted WRITE chunk | chunk length, after every shape, order, bound and duplicate check | session advances |
| Byte-identical duplicate of the last chunk | 0 | none |
| Changed duplicate, out-of-order index, bad declaration, short middle chunk | 0 | session invalidated |
| CLOSE_WRITE with wrong length or digest | 0 | session invalidated |
| CLOSE_WRITE whose response span or caller workspace is not proven RAM | 0; `6985` before any handler callback | session invalidated |
| Accepted CLOSE_WRITE, streamed result | 0; descriptor written to the RAM response span | result pending |
| Prepare failure, result length 0 or above the declared maximum, producer failure | 0 | session invalidated |
| GET_PENDING_READ_INFO, READ_CHUNK | 0; output only into a proven RAM span | none |
| READ with bad index or count, producer failure, non-RAM span | 0 | session invalidated |
| CLOSE_READ accepted, and its identical retry | 0 | read closed |
| CLOSE_READ with wrong length or digest | 0 | session invalidated |
| ABORT, deselect, reset | 0 | session gone |

Streamed result. The handler implements two callbacks per method:

```java
protected abstract short on<Method>Prepare(byte[] input, short inputOffset, short inputLength,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
protected abstract void on<Method>Produce(byte[] input, short inputOffset, short inputLength, short resultOffset,
        byte[] output, short outputOffset, short length,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
```

At CLOSE_WRITE the runtime checks the request digest, calls `Prepare` for the
total result length, then calls `Produce` chunk by chunk into the admitted
response span only to feed the result digest. Nothing is stored. The
descriptor (packet count, length, SHA-256) is written last. Each READ_CHUNK
calls `Produce` again for that chunk. `input` is the staged request and is
read-only.

`Produce` must return the same bytes every time within one prepared session.
Keep anything that cannot be recomputed (for example a randomized ECDSA
signature) in handler-owned RAM from `Prepare`. The card cannot check
determinism; the host does, because the bytes it reads must match the
descriptor digest it received at CLOSE_WRITE. `TestStreamModesRealSimulator`
shows a drifting producer being caught by that check.

Costs: the result is produced once for the digest and once per READ, and the
response span must hold one response chunk (`ensureResponseCapacity` refuses
less). Output admission is the same as the authenticated mode: a transient
array, or the current APDU buffer while the selected applet processes its APDU.

## `chunked`

| Event | Persistent stores on that APDU | Transient effect |
| --- | ---: | --- |
| Accepted WRITE chunk | 0; chunk delivered to the handler and the running digest | session advances |
| Any repeated chunk, changed or identical | 0; `6A80` | session invalidated |
| Out-of-order index, bad declaration, short middle chunk | 0 | session invalidated |
| WRITE whose caller workspace is not proven RAM | 0; `6985` before the handler | session invalidated |
| Handler refusal or failure on a chunk | 0 | session invalidated |
| CLOSE_WRITE before the last chunk, wrong length or digest | 0 | session invalidated |
| CLOSE_WRITE with a non-RAM response span or caller workspace | 0; `6985` before the handler | session invalidated |
| Accepted CLOSE_WRITE, short result | 0; result in the RAM response span | session ends; no receipt |
| Accepted CLOSE_WRITE, streamed result | 0; descriptor in the RAM response span | result pending |
| Handler failure at finish or prepare, result length rejected, producer failure | 0 | session invalidated |
| GET_PENDING_READ_INFO, READ_CHUNK, CLOSE_READ and their retries | 0; output only into a proven RAM span | as for `public-invalidate` |
| READ with bad index or count, producer failure, non-RAM span, bad CLOSE_READ | 0 | session invalidated |
| CLOSE_WRITE retry after success | 0; `6985` | none |
| ABORT, deselect, reset | 0 | session gone |

Handler callbacks:

```java
protected abstract void on<Method>Chunk(short packetIndex, short packetCount,
        byte[] chunk, short chunkOffset, short chunkLength,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
// short result
protected abstract short on<Method>Finish(short inputLength,
        byte[] output, short outputOffset, short outputCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
// streamed result
protected abstract short on<Method>Prepare(short inputLength,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
protected abstract void on<Method>Produce(short resultOffset,
        byte[] output, short outputOffset, short length,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
```

Chunks arrive exactly once and in order, read-only, from the caller's request
span. `packetIndex == 0` starts a new request: reset the parser and call
`Signature.init` there. Feed each chunk to `Signature.update` and parse fields
with a small RAM state machine. `Finish` runs only after every chunk arrived
and the runtime's running SHA-256 matched the CLOSE digest; it writes the
short result (for Auth, the single 73 B `signatureLength || signatureDerPadded`)
into the admitted RAM response span.

A chunked streamed result has no staged input: `Prepare` runs after the digest
matched, keeps what the result needs in handler RAM and returns the total
length; `Produce` then writes result bytes into the admitted RAM span for the
result digest and on every READ_CHUNK, under the same determinism contract as
the public producer. For Auth admission (INS 0x70) that is the 73 B signature
record held in RAM from `Prepare`, followed by Cert_adm evidence read in place
from its persistent record (AUTH 0x0011): no staging copy of the transcript,
the signature or the certificate.

Two choices follow from staging nothing:

- A repeated chunk cannot be compared with the one already consumed, so every
  repeat is refused and the host restarts the request.
- No receipt is kept, so an identical CLOSE retry after success is refused
  `6985`. A host that lost the response restarts the request. Keeping a
  receipt would need the result in RAM between APDUs.

The runtime starts every digest with `resetDigest()`: chunked packet 0, the
streamed result digest, and the staged CLOSE digest. An interrupted running
digest therefore never leaks into a later one; the regression witness is the
public CLOSE that follows a refused digest pass in the simulator scenario.

## Measurements

jCardSim 3.0.5.9-relux.1, both lifecycle choices, adapter route and the
Auth-shaped direct route over one APDU buffer. The ledger counts every array
element store in the generated sources and the fixture handlers, classified by
array identity; same-value stores count. Fixture `Rev4Shape`
(`codegen/testdata/Rev4Shape*.java`).

| Workload | Logical persistent stores |
| --- | ---: |
| Chunked ECDSA over a 194 B transcript (2 chunks) + 73 B response | 0 B on every APDU |
| Chunked ECDSA over 2048 B (11 chunks) + 73 B response | 0 B on every APDU |
| Chunked admission: ECDSA over a 320 B transcript, result signature + 600 B Cert_adm (673 B, 4 reads) | 0 B on every APDU |
| Chunked admission at the 1408 B result maximum (signature + 1335 B Cert_adm, 8 reads) | 0 B on every APDU |
| Public 320 B upload, 320 B streamed result (2 reads), CLOSE_READ | 320 B (upload only) |
| Public 1792 B upload, 1792 B streamed result (10 reads) | 1792 B (upload only) |
| Issuer 197 B upload + 36 B receipt | 233 B |
| Every refusal, ABORT, deselect, reset, read retry, CLOSE_READ retry | 0 B each |

Reachable generated array payload for the real Auth fixture on jCardSim,
clear-on-reset (`TestStreamModesAllocationPayload`):

| Shape | Skeleton-reachable transient | Persistent (workspace + tables) | Workspace |
| --- | ---: | ---: | ---: |
| `authenticated-invalidate`, Auth without its two response streams | 72 B | 2132 B | 2048 B |
| REV4 modes, full Auth IDL (9 streamed methods) | 74 B | 2165 B | 2048 B |

The 2 B RAM delta is the mode scalar. The 33 B persistent delta is install-time
tables (two INS bases, two direction bytes, two limit rows, nine mode bytes),
never written per command. The streamed results (1792 B and 1408 B declared)
take no generated RAM or NVM: they live in the caller's response span. The
generated adapter adds its 255 B transient I/O array if the applet constructs
it. Object headers, provider and JCRE arrays are excluded. This is a generator
payload, not a card total.

## Not established here

- Signature, MessageDigest and RandomData internal state, JCRE transaction
  journaling and physical EEPROM wear are outside the ledger. Whether a card's
  `MessageDigest.update` or `Signature.update` keeps intermediate state in
  EEPROM is implementation-defined and unknown, not zero.
- Handler RAM is the consumer's: parser state, a held signature or nonce, and
  any scratch. A card-wide RAM total must add it to every applet's reserve.
- Route B (Security Domain selected): `APDU.getCurrentAPDUBuffer()` is not
  available, so the consumer must pass transient spans. jCardSim does not
  enforce that context.
- Physical-card behavior, the Auth transcript parser, Auth provisioning and
  admission producers and their determinism are downstream consumer work.

## Evidence

`codegen/gen_java_stream_modes_test.go`:

- `TestStreamModeValidation`, `TestStreamModeGenerationNarrowingMutants` (two
  Go mutants, each admitting one INS in one refused class);
- `TestStreamModesKeepAuthenticatedOutput` (L2 and released Auth outputs
  byte-identical, with a positive control);
- `TestStreamModesSourceContract` and `TestStreamModesTokenPreservingMutant`;
- `TestStreamModesRealSimulator` (the scenario above);
- `TestStreamModesLedgerControls` (a same-value 1 B persistent store planted on
  a refusal path, directly and through an alias, on the accepted chunked path
  and on an accepted producer read is caught by name; a transient plant stays
  green);
- `TestStreamModesNarrowingMutants` (31 behavioral mutants, each keeping its
  guard and admitting one member of the refused class);
- `TestStreamModesAllocationPayload` and `TestStreamModesClassicCAP` (Classic
  3.0.5u4 conversion with a fixture using every callback and `Signature.update`).
