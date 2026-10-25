# Persistent stream workspace cleanup

The measurements below describe the pre-ordinary-writer release and retained
historical experiments. The ordinary Java source API has since migrated to
caller-owned output spans; see [current writer target measurements and
verification bounds](ORDINARY-OUTPUT-SPANS.md#measurement-scope).

The explicit Applet.StreamWorkspaceCleanup selector supports only
whole-reply-area, and requires Applet.StreamWorkspace == "persistent".
Unknown selectors, written-bytes-only and nonpersistent combinations are refused
before returning any generated files. Empty cleanup preserves the released
output, including default persistent full cleanup; scalar wire protocol and
stream raw-array handler signatures are unchanged. Published pluginapi/v0.1.1 retains its
unused written-mode constant as a compatibility symbol, not a supported mode.

Request copies track their exact successful prefix; retries write nothing.
Before invoking a handler, whole-reply-area marks its entire authorized reply
capacity, covering exceptions and scratch beyond returned length. Cleanup erases
the union of that region and the request prefix. Untouched workspace is skipped
on abort, deselect and ordinary failure. First successful READ close erases once;
its retry retains the receipt without a repeated wipe. Short-response results
remain available for close retries until normal cleanup.

Reset loses the transient frontier: the next stream dispatch or abort retains
its full workspace sweep. This reset cost has not been optimized. The opt-in
marker is CLEAR_ON_RESET, so normal deselect does not cause another lazy full
sweep. Wiping is nontransactional; torn-write atomicity is outside this claim.
Whole reply adds 2 B to the existing transient short array and no arrays.

## Historical mode selection

The 2026-10-08 release decision keeps whole-reply-area and rejects
written-bytes-only. The tables retain the measured three-mode experiment,
including the rejected confined Input/Writer implementation. Those types,
methods, state and source branches have been removed from the shipping backend.
Consumer-specific writer experiments and their measurements are excluded from
this library contract. Whole reply preserves the raw handler API with a 2 B
transient-state increase.

## Counting scope and reproducibility

`TestPersistentCleanupExampleComparison` installs a real generated example on
jCardSim and drives `Simulator.transmitCommand -> Applet.process ->
processIfStream -> dispatchStreamTo -> BoundedStreamRuntime.dispatch`. The
observer counts executed byte stores, including same-valued zero stores, and
successful bulk-copy lengths, separating data stores, cleanup and reset sweeps.
No formula substitutes for executing a handler. Constructor/installation stores
are outside the session counters. Additional mutable control state is transient;
its logical NVM writes per command are zero. Mutable applet business state,
cryptographic provider/JCRE state and transaction logging are outside the example
workspace counter.

The call observer counts entries into generated adapter, skeleton, runtime and
fixture methods; ranges below are observed minima and maxima over actual APDU
commands. JCRE, Java Card crypto/Util internals, host harness methods and inlined
physical-card call costs are outside this count. RAM is the reachable generated
primitive array payload. Object headers, provider/JCRE arrays and physical
reference widths are excluded; reference slots are reported separately.

Toolchain: Go 1.25.5; OpenJDK 17.0.18 for jCardSim 3.0.5.9-relux.1; OpenJDK
11.0.32.1 and ant-javacard for SDK 3.0.5u4 conversion/verification. Simulator JAR
SHA-256: `fd6e1289d0a337c5ac1dc9624bc46cf8717bd162228d8d801ada9615ba3d122a`.
Ant JAR SHA-256: `779909502744af7eb8c24b7b423c4efa6fbf47a1274a11ddf8c49697b1028e64`.

```sh
JCRPC_JCARDSIM_JAR=/path/jcardsim-3.0.5.9-relux.1.jar \
  go test ./codegen -run 'TestPersistentCleanup.*(Lifecycle|Mutants|Comparison|Plant)' -count=1 -v
JAVA_HOME=/path/jdk11 PATH=/path/jdk11/bin:$PATH \
  JCRPC_ANT_JAVACARD_JAR=/path/ant-javacard.jar \
  JCRPC_JCKIT_DIR=/path/jc305u4_kit \
  go test ./codegen -run TestPersistentCleanupCAP -count=1 -v
```

## Generated example measurements

Current executable comparison covers released default and whole reply. The
written-byte rows are historical results from the pre-removal generator and
fixture; they do not describe a supported selector.

The example's request/response limit is 1792 B, chunk size 192 B. Provisioning
runs 1792 B in / 1792 B reversed out. Issuance uses 320 B in / 320 B reversed out.
These are synthetic reverse-buffer workloads, not consumer operations. Failure
buffers 896 B and explicitly aborts before handler entry. Untouched runs SELECT
and an ordinary generated version read, then deselects. Each workload has a
fresh simulator installation and ends with actual deselection/reselection.

| Workload | Mode | Data stores | Cleanup stores | Included reset sweep | Total workspace NVM/session | Stores at deselect | APDU commands | Owned method entries/command |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Untouched | Released default | 0 B | 1792 B | 0 B | 1792 B | 1792 B | 1 | 9 |
| Untouched | Whole reply | 0 B | 0 B | 0 B | 0 B | 0 B | 1 | 9 |
| Untouched | Written bytes (rejected) | 0 B | 0 B | 0 B | 0 B | 0 B | 1 | 9 |
| Provisioning | Released default | 3584 B | 5376 B | 1792 B | 8960 B | 1792 B | 22 | 14–32 |
| Provisioning | Whole reply | 3584 B | 1792 B | 0 B | 5376 B | 0 B | 22 | 15–33 |
| Provisioning | Written bytes (rejected) | 5376 B | 1792 B | 0 B | 7168 B | 0 B | 22 | 15–14377 |
| Issuance | Released default | 640 B | 5376 B | 1792 B | 6016 B | 1792 B | 6 | 14–32 |
| Issuance | Whole reply | 640 B | 1792 B | 0 B | 2432 B | 0 B | 6 | 15–33 |
| Issuance | Written bytes (rejected) | 960 B | 320 B | 0 B | 1280 B | 0 B | 6 | 15–2601 |
| Mid-stream failure | Released default | 896 B | 5376 B | 1792 B | 6272 B | 1792 B | 6 | 14–18 |
| Mid-stream failure | Whole reply | 896 B | 896 B | 0 B | 1792 B | 0 B | 6 | 15–17 |
| Mid-stream failure | Written bytes (rejected) | 896 B | 896 B | 0 B | 1792 B | 0 B | 6 | 15–17 |

Reset is a subset of cleanup, not an extra addition to the total. In the fresh
installation transcript the released CLEAR_ON_DESELECT marker is already clear
before the first stream dispatch, so its lazy full sweep is measured and shown
separately. Explicit modes avoid this deselect-driven sweep. A real reset still
adds one full 1792 B sweep in either explicit mode, proved in the lifecycle lane.
The strict reverse handler first uses an in-place bulk input copy to establish
its writable prefix, then swaps bytes; those additional stores and method
entries are counted. They are an example algorithm cost, not a requirement that
every migrated handler incur that count.

| Generated footprint | Released default | Whole reply | Written bytes (rejected) |
| --- | ---: | ---: | ---: |
| Transient primitive payload | 328 B | 330 B | 340 B |
| Transient reference slots | 1 | 1 | 2 |
| Reachable generated arrays | 13 | 13 | 13 |
| Persistent workspace | 1792 B | 1792 B | 1792 B |
| Persistent dispatch-table payload | 24 B | 24 B | 24 B |
| Additional control NVM writes/command | 0 B | 0 B | 0 B |
| Generated Java sources, five files | 44448 B | 45356 B | 50029 B |
| CAP uncompressed components | 6591 B | 6731 B | 8385 B |
| Method.cap component | 3745 B | 3837 B | 4527 B |
| CAP ZIP including metadata | 42718 B | 43316 B | 56986–56987 B |

CAP components and Method.cap are exact byte inventories; ZIP compression and
metadata can vary by a byte. Both transient lifecycle choices were converted and
verified. The historical confined variant added two preallocated capability objects; their
physical headers are not included in array payload. It expanded an existing
short array by 12 B and the existing reference array by one slot; whole reply
expands the short array by 2 B. Command-path array inventory remains unchanged.

## Consumer measurements

Consumer measurements belong to their own workspaces. The synthetic generator
examples above establish only their declared observation boundaries; they do
not establish another application's memory, storage or hardware behavior.
