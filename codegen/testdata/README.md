# Compatibility fixtures

The corpus contains the independent counter, bounded-stream, counter-example
and synthetic SampleStore inputs. SampleStore is authored as record/page storage,
not a consumer API. Its TOML SHA-256 is
`46729b4e03cc71d6997de286c2361271a1c281fbc7839556c79de031a2b63847`.

Its baseline outputs were independently produced by signed facade v0.4.5
(commit `cfed4182356a4f4609c88f58924aac79c05ae5b6`), executable SHA-256
`adb7c8b8402413391eda07083dbe1512333e44fe4b00d10c2abd324b72bfedf6`.
The Java matrix adds all54 workspace/lifecycle/simulator/namespace combinations.
Kotlin packages retain both namespaces. Swift records the intended stream
refusal. The other three inputs retain their existing baseline provenance.

Current source-projection receipts freeze a reviewed API delta only; they are
not independent behavior, allocation or physical-device evidence. Package order,
bytes/hashes, complete matrix coverage and input nonmutation remain tested.

`TestPluginReleasedV045Parity` uses two sources of expectations per row:
`parity-v0.4.5.json` supplies retained historical generation for settings,
build files and transports; `caller-workspace-v0.5.0.json` supplies current-source
receipts for skeletons, stream endpoints, bounded runtimes and APDU adapters.
The latter file's version-shaped name is not historical provenance.
`sample-store-default-projection.json` and
`sample-store-whole-projection.json` are also current-source receipts.
None of these projection receipts may replace retained historical hashes.

ModeStore is an independently specified circular storage example. Requests to
inspectOffsets/readWindow contain big-endian u16 relative seeks; FFFF is
reserved and partial words are refused. Inspection returns word count, cursor
modulo 1280 and word XOR (three u16 fields). Reading returns only a circular
window of the installed store; it has no proof prefix. Page preview reverses
the staged page; authenticated description returns u32 length plus SHA-256.
The harness computes cursors with host int arithmetic and checks store bytes
against the installation formula, independently of applet state.

`batch-store-authenticated-projection.json` records the five generated sources
for each lifecycle choice of the independent BatchStore helper in
`gen_java_authenticated_test.go`. It was captured from the current cleanup
candidate, not a released generator. It pins source bytes only. The separate
real-simulator positive/refusal/ledger-control tests and Classic converter
checks qualify behavior and conversion; this file supplies neither proof.

BatchStore's 29-byte simulator/CAP summary encodes a zero-padded 21-byte input
prefix, u32 input byte count, u16 format 1, u8 state 1 and bool true (01).
Its 11-byte position encodes u32 offset 0, u32 used input bytes, u16 flags 0
and u8 state 1. Host ByteBuffer decoding checks the typed fields separately;
the E3-at-input-offset-28 regression vector would have produced invalid E2
under the former transform. Handler/harness bytes are not part of the
generated-source projection receipt.
