# javacard-rpc-server-javacard v0.3.0

This release adds the Java Card Go code-generation backend alongside the existing
on-card runtime. Both components use the canonical root tag `v0.3.0` and its
single repository commit.

## Consumer pins

| Component | Exact pin |
| --- | --- |
| Go backend module | `github.com/relux-works/javacard-rpc-server-javacard v0.3.0` |
| Go package | `github.com/relux-works/javacard-rpc-server-javacard/codegen` |
| Backend API dependency | `github.com/relux-works/javacard-rpc/pluginapi v0.1.0` |
| Runtime source tag | `v0.3.0` in this repository |
| Runtime Gradle version / coordinates | `0.3.0` / `io.jcrpc:javacard-rpc-server-javacard:0.3.0` |
| Runtime Java package | `io.jcrpc.server` |

Resolve the shared source commit with `git rev-parse 'v0.3.0^{commit}'` after
cloning this repository, and verify the root tag with `git verify-tag v0.3.0`.
The [README](README.md#version-pins) shows the backend dependency and runtime
source-build commands. Maven group/artifact names and Java package names remain
unchanged; the Gradle version advances from `0.1.0` to `0.3.0`.

## Changes and compatibility

- `codegen.Plugin{}.Generate(schema, options)` consumes validated
  `pluginapi.Schema` and explicit `pluginapi.Options`, returning ordered files
  in memory. The package has no facade, TOML parser or filesystem publisher
  dependency; its only external Go dependency is released `pluginapi v0.1.0`.
- Java renderer behavior and the on-card runtime source are preserved. Output
  bytes and file ordering match the signed core `javacard-rpc v0.4.5` baseline
  at commit `cfed4182356a4f4609c88f58924aac79c05ae5b6` across all 216 distinct
  Java Card parity cells. This does not imply compatibility with every later
  facade version.
- Invalid workspace/memory policies and missing required options return errors
  without a partial package. Parsing, schema validation, CLI defaults and safe
  file publication belong to the consumer or facade.
- Persistent workspace cleanup retains the core v0.4.5 behavior. This release
  makes no change to proportional wiping, physical NVM endurance or interruption
  atomicity.

## Toolchains and supported-platform limits

The backend requires Go 1.25+. The root runtime builds with JDK 17 and Gradle
8.12, retaining Java 8 source/bytecode compatibility and the upstream
`com.klinec:jcardsim:3.0.5.9` dependency. Verification used Go 1.25.5 and
JDK 17.0.18 on macOS arm64.

The native evidence covers actual root-runtime APDU dispatch/refusal/recovery
through jCardSim, generated workspace lifecycle/allocation controls, and four
CAP conversion/verifier variants with Java Card SDK 3.0.5u4, JDK 11.0.32.1,
Ant 1.10.17 and ant-javacard v26.02.22. The full lifecycle simulator lane uses
Relux jCardSim `3.0.5.9-relux.1`; upstream `3.0.5.9` rejects the
`CLEAR_ON_RESET` digest construction. Select the simulator dependency explicitly
when generating that variant.

These host/simulator/converter checks do not establish installation or behavior
on a physical card, handset OMAPI support, iOS SIM access, or Kotlin/Swift target
compatibility. Optional native tests skip when their toolchain variables are
unset; the README's required Make lanes reject missing configuration. A default
Go test pass alone does not establish CAP or simulator coverage.
