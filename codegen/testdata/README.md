# Java Card regression fixtures

The JSON schemas are frozen normalized models exported using `ParseFile` and
`Validate` from core commit `ef6e04bfae8dab0f8e1ac40c9bb10713dbf09250`.
They cover the complete core parity input set: the example counter, test counter,
test stream, and the pinned bsim-auth IDL at B6 commit
`2d23abdafa1e0f68c6003ab56274b2ac38378ef9` (original TOML SHA-256
`1be1ed52ac9a85a62d5c5e371a9e22d38f834282681528476ca071e7bfc2cb66`).
No parser is part of this backend module.

`parity-v0.4.5.json` pins hashes of every ordered package file obtained by running
an independent CLI built from the signed published core `v0.4.5` tag. Its header
records the release commit and binary SHA-256. Its 216 rows are the distinct
JavaCard projection of the complete 720-cell core matrix: four inputs, three
workspace policies, three lifecycle choices, three simulator options (default,
explicit upstream, explicit Relux), and two namespaces (explicit and `--all`
default). Duplicate Java selections in combined-target CLI cases collapse to
these same rows. Tests compare the target's actual `Plugin.Generate` files.
Empty simulator choices are expanded by the test consumer, as the facade does.

CLI help, selector dispatch, parsing/IDL validation, invalid CLI simulator syntax,
and Kotlin/Swift output are owned by the facade and outside target extraction.
Unknown workspace and transient-memory options are also checked directly against
the plugin, requiring no partial package. Namespace/schema refusals have valid
controls. The full raw CLI matrix remains a core compatibility test.

The Java golden files and JVM harnesses are maintained target fixtures. Original
JavaCard regression test names are retained; their test-only generation helpers
now unpack `Plugin.Generate` instead of calling renderer wrappers. The policy
test drives backend policy refusal directly; it does not claim parser coverage.
CAP and real simulator checks require explicit toolchain configuration and are
separate from the JVM stand-in lane. No physical card or NVM endurance claim is
made. Persistent cleanup remains exactly as v0.4.5; proportional wiping is deferred.

The v0.5.0 caller-workspace API separately freezes 540 changed file hashes across
the same 216 rows in `caller-workspace-v0.5.0.json`: every skeleton, and each
stream endpoint/runtime/adapter. Other files still match the independent release
matrix. `ordinary-writer-skeletons.json` remains the historical v0.4.0 projection.
The new projection is candidate source identity, not an independent behavioral
oracle. Existing named reviewer tests and all fixtures migrate the trailing
scratch triple; the counter golden is regenerated from the maintained schema.

`CallerWorkspaceLogic.java` is the trusted CAP-compatible business fixture with
explicit 196/260 phase minima, precise input-last-consumer ordering and no borrowed
buffer fields. `CallerWorkspaceHarness.java` supplies independent identity/span,
boundary/refusal/retry, result lifetime and generated-field retention oracles.
Its host-only subclass retains expected test references deliberately; generated
classes and the CAP logic do not. `CallerWorkspaceApplet.java` and
`CallerWorkspaceAPDUHarness.java` drive the actual simulator process/send path.
See [the API and evidence limits](../../CALLER-WORKSPACE.md).
