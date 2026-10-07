# Persistent stream workspace cleanup

The explicit Applet.StreamWorkspaceCleanup selector supports only
whole-reply-area, and requires Applet.StreamWorkspace == "persistent".
Unknown selectors, written-bytes-only and nonpersistent combinations are refused
before returning any generated files. Empty cleanup preserves the released
output, including default persistent full cleanup; scalar wire protocol and raw
array handler signatures are unchanged. Published pluginapi/v0.1.1 retains its
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
The historical writer bridged real Auth SDK array APIs with a 2048 B transient
staging arena. It reduced observed stores on some workloads but added 2062 B attributed RAM
against baseline; provisioning wrote 103 B more than whole reply. Whole reply
preserves the raw handler API with a 2 B transient-state increase.

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
runs 1792 B in / 1792 B reversed out. Issuance uses 320 B in / 320 B reversed out,
which differs explicitly from Auth's certificate/admission workflow. Failure
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

## Real Auth historical comparison and selected whole mode

Real Auth runs CardSimulator.transmitCommand -> BSimAuthApplet.process ->
generated dispatch -> actual Auth operations on released KeyVault/crypto.
Five session classes include actual deselect. Setup/installation are outside the
measurement window. Valid payloads replace earlier capacity-only proposals:
311/305 B challenge/session, 1330 B signed bootstrap, accepted 640 B Cert_sim,
172 B possession, 224 B anchor and 155 B admission, plus actual Cert_adm and
footprint. Failure aborts after 384 B of a genuine 579/580 B leaf, then proves
idempotent recovery; it is not exactly half. 641/2048 B refusals are negative
tests, not successful workloads. Random card keys/signatures cause 1 B DER
variation; wire format and product semantics are checked, not cross-card byte
equality of random ciphertext.

NVM here is logical primitive-array payload stores by instrumented
Auth/generated code into Auth-owned persistent arrays, including same-valued
zeros and successful copies. Workspace is separate; issuance adds 409 B in other
owned arrays. Released KeyVault/crypto, primitive persistent fields,
allocation/initialization and platform internals are excluded. Provider-origin
stores outside the observed class inventory are outside this metric: it is not
a total card or all-origin NVM measurement. There is no separately measured Auth
reset sweep or data/cleanup split; no category is inferred from a formula.
The native lifecycle separately proves the retained full reset sweep.

Auth RAM is TransientLedger attributed arrays/transient key containers, including
2 B reference slots; example RAM above counts primitive payload and reports
reference slots separately. Engine-private/temporary RAM and object headers are
excluded. Auth CAP is GP Load File Data Block bytes excluding Descriptor.cap;
example CAP above inventories uncompressed components and ZIP, so the columns
have different scopes. Calls count Auth/generated method entries per APDU,
excluding libraries/platform and SELECT/deselect. Exact total/APDU ratios and
ranges are shown.

| Workload | Mode | Valid input | Real output | Observed Auth stores | Observed workspace stores | Auth RAM | Auth CAP | APDUs | Calls/APDU mean (range; total/APDUs) |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| plain-authentication | v0.4.6 | 311+305 B | 73+73 B | 5000 B | 5000 B | 1797 B | 30541 B | 6 | 45.00 (19..95; 270/6) |
| plain-authentication | whole-reply-area | 311+305 B | 73+73 B | 1520 B | 1520 B | 1799 B | 30653 B | 6 | 46.00 (20..96; 276/6) |
| plain-authentication | written-bytes-only (rejected) | 311+305 B | 73+73 B | 1378 B | 1378 B | 3859 B | 32565 B | 6 | 57.33 (20..130; 344/6) |
| provisioning | v0.4.6 | 1330 B | 1283 B | 6144 B | 6144 B | 1829 B | 30541 B | 16 | 131.19 (19..1796; 2099/16) |
| provisioning | whole-reply-area | 1330 B | 1283 B | 3840 B | 3840 B | 1831 B | 30653 B | 16 | 131.69 (20..1797; 2107/16) |
| provisioning | written-bytes-only (rejected) | 1330 B | 1283 B | 3943 B | 3943 B | 3891 B | 32565 B | 16 | 133.81 (20..1831; 2141/16) |
| issuance | v0.4.6 | 640+172+224+155 (+485 Cert_adm) B | 36+73+38+1023 (+190 footprint+36 Cert_adm) B | 15722 B | 15313 B | 1797 B | 30541 B | 24 | 109.00 (21..967; 2616/24) |
| issuance | whole-reply-area | 640+172+224+155 (+484 Cert_adm) B | 36+73+38+1022 (+190 footprint+36 Cert_adm) B | 6360 B | 5951 B | 1799 B | 30653 B | 24 | 109.67 (21..968; 2632/24) |
| issuance | written-bytes-only (rejected) | 640+172+224+155 (+485 Cert_adm) B | 36+73+38+1023 (+190 footprint+36 Cert_adm) B | 5835 B | 5426 B | 3859 B | 32565 B | 24 | 116.75 (21..1002; 2802/24) |
| untouched-identity | v0.4.6 | 0 B | 127 B | 2048 B | 2048 B | 1797 B | 30541 B | 1 | 32.00 (32..32; 32/1) |
| untouched-identity | whole-reply-area | 0 B | 127 B | 0 B | 0 B | 1799 B | 30653 B | 1 | 32.00 (32..32; 32/1) |
| untouched-identity | written-bytes-only (rejected) | 0 B | 127 B | 0 B | 0 B | 3859 B | 32565 B | 1 | 32.00 (32..32; 32/1) |
| failure-mid-leaf | v0.4.6 | 384 of 580 B | 0 B | 4480 B | 4480 B | 1797 B | 30541 B | 3 | 22.67 (21..25; 68/3) |
| failure-mid-leaf | whole-reply-area | 384 of 580 B | 0 B | 768 B | 768 B | 1799 B | 30653 B | 3 | 23.33 (22..25; 70/3) |
| failure-mid-leaf | written-bytes-only (rejected) | 384 of 579 B | 0 B | 768 B | 768 B | 3859 B | 32565 B | 3 | 23.33 (22..25; 70/3) |

Measurement identity: immutable Auth base jc
1c51cca5129210b5404b481f850e512832cb88d3; isolated signed comparison fixture
124a24f2bfc84d7bb27d93400c073eda2ddae268; bsim-id
0e478af50d998250b41d6e292d1a3a5009052552 and unchanged IDL blob
1797ac2e56e4a81cf9fc896568bd31b22dec8b10. Baseline generator is released facade
v0.4.6 at 995513e85e601759dadbe496d9897c36ec4d5a82. Auth uses macOS arm64,
JDK17 17.0.18, Gradle 9.2.1 and jCardSim 3.0.5.9-relux.2 (JAR SHA-256
485617e913bef9803404d32d2d4f36b5410bf7d298c3ff147e0e1b4d27d3262a).
CAP uses JDK11 and SDK 3.2 converter targeting JC 3.0.5 with the pinned
GlobalPlatform imports. This is distinct from the example relux.1/SDK3.0.5u4
lane. The earlier relux.3 migration event is not comparison evidence.

Reported upper bounds on omitted whole-mode library output stores are 146 B
for plain authentication, 1283 B provisioning and approximately 1170 B plus
footprint for issuance (exact components and DER variation above); untouched
and failure omit 0 B. These are bounds, not manufactured actual store counts.
Whole-versus-writer NVM differences are not exact all-origin totals. The owner
selected whole reply: the rejected writer adds 2060 B attributed RAM and 1912 B
CAP against whole mode. No universal percentage reduction is claimed.

| Auth generated Java sources, five files | Default | Whole reply | Written bytes (rejected) |
| --- | ---: | ---: | ---: |
| Source bytes | 58659 B | 59570 B | 63426 B |

The narrowed whole-only generator emits the exact five measured Auth Java
sources (59570 B), verified by TestPersistentCleanupWholeMeasuredAuthIdentity
through Plugin.Generate. Runtime SHA-256 is
5063f440b42c08619274cd16206541c55c98004acd3e3c8b727c26e9af9fb90f;
all five hashes are asserted. This output identity reuses the measured whole
CAP/session data despite removal of inactive writer source. Historical fixture
reports 173 green Auth tests, 19 killed narrowing controls and three verified CAP
builds; writer-specific tests and RAM are historical, not shipping behavior.
The request observer omitting exactly offsets768..959 fails the named
provisioning counter assertion (1330 versus1138); a frontier384 wipe narrowed to
192 fails failureMidLeaf workspace residue. No omitted store is inferred from
a successful status alone.

No simulator timing is measured. Physical timing, endurance, total physical RAM,
torn-write behavior and NovaCard remeasurement remain consumer physical-card work.
