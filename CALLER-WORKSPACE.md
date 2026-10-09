# Caller workspace API (v0.5.0)

v0.5.0 appends an explicit borrowed scratch triple to the generated Java API.
The entry owner supplies its actual legal array/window. Request/input and
result/output triples remain separate. Regenerate all maintained subclasses and
adapters; old signatures have no overload or compatibility shim. IDL, INS,
wire encodings, fixed reply widths and stream session ownership are unchanged.

## Copyable ordinary migration

```java
public final short dispatchTo(byte ins, byte p1, byte p2,
        byte[] requestBuffer, short requestOffset, short requestLength,
        byte[] output, short outputOffset, short outputCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);

// Request arguments first, then writer output when applicable, then scratch.
protected abstract short onGetAuthenticationIdentity(
        byte[] output, short outputOffset, short outputCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
protected abstract short onEcho(short prefix,
        byte[] payload, short payloadOffset, short payloadLength,
        byte[] output, short outputOffset, short outputCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);

// Scalar and void return types stay unchanged, including when scratch is unused.
protected abstract short onGetCount(
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
protected abstract void onReset(
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
```

At an ordinary APDU entry, receive the entire request and capture INS/P1/P2
before overlapping writes. The following example explicitly lends the current
APDU array; a caller with another legal window passes that window instead.

```java
byte[] buffer = apdu.getBuffer(); // command-local, never a field
short produced = logic.dispatchTo(ins, p1, p2,
        buffer, requestOffset, requestLength,
        buffer, outputOffset, outputCapacity,
        buffer, scratchOffset, scratchCapacity);
// Map StatusWordException to ISOException in the caller. Only send after success.
if (produced > 0) {
    apdu.setOutgoing();
    apdu.setOutgoingLength(produced);
    apdu.sendBytesLong(buffer, outputOffset, produced);
}
```

Every ordinary callback receives the same scratch object/offset/capacity from
this call, including scalar/void callbacks. Fixed writers still receive exactly
the IDL reply width (for example 127/190/177), even when independent scratch is
196/260 bytes. Fixed produced count must equal that width; variable count must
be within the offered output capacity. Scratch never widens reply authority.
Generated names use the existing allocator against all IDL fields, occupied
suffixes and generated companion/local names. Override types/order are stable;
parameter spellings may acquire suffixes to avoid valid IDL name collisions.

## Copyable stream migration

```java
public final short dispatchStreamTo(byte ins, byte p1, byte p2,
        byte[] requestBuffer, short requestOffset, short requestLength,
        byte[] responseBuffer, short responseOffset, short responseCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);

protected abstract short onUploadStream(
        byte[] input, short inputOffset, short inputLength,
        byte[] output, short outputOffset, short outputCapacity,
        byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);
```

The same trailing triple is required by `StreamEndpoint.dispatch`,
`BoundedStreamRuntime.dispatch`, `Handler.execute`, skeleton `execute` and every
`onMethodStream` override. `executeOnce` passes it through as command-local
parameters. CLOSE_WRITE uses that CLOSE_WRITE entry's scratch, not an earlier
WRITE chunk's scratch. Response-only WRITE_OR_INVOKE uses that invocation's
scratch. The runtime's owned bulk storage remains the input/result session
buffer. Neither owned bulk nor the response span reconstructs scratch authority.

```java
short produced = logic.dispatchStreamTo(ins, p1, p2,
        request, requestOffset, requestLength,
        response, responseOffset, responseCapacity,
        actualCallerWorkspace, actualCallerWorkspaceOffset, actualCallerWorkspaceCapacity);
```

The generated APDU adapter passes its actual command-local `apdu.getBuffer()`
with offset zero and that array's capacity. It continues to receive/send through
its existing 255-byte I/O scratch, wipe I/O on exit and retain owned session
results for later reads. No global APDU lookup or borrowed reference is stored.
Handwritten APDU/SIO adapters supply the legal window their entry owns; no
constructor injection, global array field, object-array slot or ThreadLocal is
allowed for borrowed arrays. The owned business handler slot remains unchanged.

## Bounds, effects, aliasing and physical limits

Scratch must be nonnull, with nonnegative offset/capacity contained in the
array. Offset equal to array length is valid only at zero capacity. Validation
uses subtraction after offset validation, so short addition overflow cannot
admit an out-of-array span. Framework code accepts a valid empty window;
consumer phases decide their own minimum. No Auth-specific 196/260 constant is
part of generic code generation.

Ordinary dispatch validates request, output and scratch before callbacks.
Stream dispatch validates scratch before reset cleanup, state changes and the
exception cleanup boundary. Invalid scratch returns `6700` and leaves a valid
pending write/read session available for retry. Existing request/output/protocol
failures keep their existing cleanup/refusal semantics. Handler errors and
invalid produced lengths still expose no sendable result and clean the stream
session. Exact short replies, CLOSE_WRITE receipts, replay, read lifetime,
abort/reset/deselect and allocation policies remain in force.

Input, output and scratch can deliberately alias. Trusted handlers must consume
input through its last consumer before overwriting overlapping bytes, and must
preserve produced output through its final send/read. Generated stream outputs
remain session-owned; write them after scratch use when the two overlap. The
runtime does not sandbox malicious stores, enforce handler bytecode isolation or
roll back business writes. A valid but phase-undersized window must be rejected
by that phase before its protected effects.

Arrays and spans follow Java Card Classic's short-indexed array model. A
physical 133-byte APDU buffer cannot satisfy a 196-byte constructor probe or a
260-byte phase geometry, nor a whole 177/190-byte reply. A larger host/simulator
array is no evidence of physical card capacity or Security Domain borrowing
permissions. The business fixtures prove only those declared numeric minima,
not the real Auth crypto/provider/SD chain. Optional `int` support remains
required by the current Classic renderer. Physical installation, Auth/RAM/NVM
acceptance and coordinated consumer regeneration belong to the consumer/release
owners after actual signed source publication.

## Executable qualification

`TestCallerWorkspaceJVM` runs six named behavioral groups through generated
`dispatchTo` and `dispatchStreamTo`: all ordinary shapes, both stream execution
paths, exact identity/nonzero offsets, 127/190/177 widths, disjoint and overlap
last-consumer/read lifetime, null/negative/overflow/end boundaries, 133 and
just-below/exact 196/260 phases, no effects/partial reply on the specified
refusals, valid retries and generated reference inspection. It runs transient
and persistent storage with both lifecycle modes, plus explicit whole-reply
cleanup. Reflection inspects generated fields/static/object components; it does
not audit arbitrary business-handler graphs or prove physical SD permissions.

`TestCallerWorkspaceNarrowingMutants`, `TestCallerWorkspaceReferenceMutants` and
`TestCallerWorkspaceConsumerMinimumMutants` retain guards and require named
behavioral assertion failures with JVM exit 1. Token-preserving wrong-buffer,
wrong-offset, span-widening, cleanup and count plants execute the behavioral
suite. A missing anchor, compilation error, crash or unnamed failure is not a
kill. `TestCallerWorkspaceSourceContract` independently derives API membership
from the input IDL and states its source-text limits. Existing reviewer tests
retain their original names; the hygiene corpus also includes the three new
scratch names and their occupied suffixes.

`TestCallerWorkspaceAdapterBehavior` additionally observes current APDU identity
through actual generated `processIfStream` on bounded JCRE stubs, with three
token-preserving adapter plants in `TestCallerWorkspaceAdapterMutants`.
`TestCallerWorkspaceResetGuardMutant` moves the intact guard after reset cleanup
and detects the forbidden persistent wipe using controlled reset state.
`TestCallerWorkspaceLivenessMutants` changes trusted fixture store ordering and
detects last-consumer/output-final-read damage. Real reset/deselect behavior is
established by the retained native lifecycle suites, not the controlled marker.

`TestCallerWorkspaceRealSimulator` executes the actual Applet.process/send and
stream adapter through Simulator.transmitCommand. `TestCallerWorkspaceClassicCAP`
compiles, converts and verifies mixed ordinary+stream classes on the real kit for
six storage/cleanup/lifecycle variants. With `JCRPC_CAP_EVIDENCE_DIR` set, it
retains each CAP and full converter/verifier log there. These gates establish
source/toolchain behavior, not physical card installation or signed publication.
