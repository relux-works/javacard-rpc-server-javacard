# javacard-rpc-server-javacard

Java Card code-generation backend and on-card runtime for
[javacard-rpc](https://github.com/relux-works/javacard-rpc). The root repository tag
versions both components: the Go backend lives in codegen/ and the Java runtime
keeps its normal root Gradle layout. The `v0.4.0` release candidate pairs Go module
version `v0.4.0` with runtime version `0.4.0` at the same repository commit. Runtime
coordinates are `io.jcrpc:javacard-rpc-server-javacard:0.4.0`; the group, artifact
name and Java package `io.jcrpc.server` are unchanged.

## Version pins

Use the root module version for the backend:

The following pins and tag commands apply once `v0.4.0` is published.

```sh
go get github.com/relux-works/javacard-rpc-server-javacard@v0.4.0
```

Build the runtime from the same root tag with the included Gradle wrapper:

```sh
git clone https://github.com/relux-works/javacard-rpc-server-javacard.git
cd javacard-rpc-server-javacard
git verify-tag v0.4.0
git checkout --detach v0.4.0
git rev-parse 'v0.4.0^{commit}'
./gradlew build --no-daemon
```

The peeled tag commit identifies both components; the runtime jar is
`build/libs/javacard-rpc-server-javacard-0.4.0.jar`. These instructions build
from source; they do not require a Maven repository publication. See
[release notes](RELEASE-NOTES-0.4.0.md) for compatibility and verification limits.

## Requirements

- Go 1.25+ for the backend and host regression tests
- JDK 17 and the included Gradle wrapper for the runtime
- Ant, ant-javacard and Java Card SDK 3.0.5 with JDK 11 for the CAP lane

## Backend API

Import github.com/relux-works/javacard-rpc-server-javacard/codegen and call
codegen.Plugin{}.Generate(schema, options). The only external Go dependency is
released github.com/relux-works/javacard-rpc/pluginapi v0.1.1; there is no local
replace or facade/parser/render dependency.

The plugin consumes a validated pluginapi.Schema and explicit pluginapi.Options,
and returns a complete ordered Gradle package in memory. It performs no file
writes. The facade owns TOML parsing, IDL validation, namespace/default-option
selection, simulator-coordinate validation and safe publication of returned
files. Consumers must supply Namespace and SimulatorDependency (for example
com.klinec:jcardsim:3.0.5.9); empty StreamMemory retains the released default.
Unknown workspace or memory policies return an error without a partial package.
Explicit `Applet.StreamWorkspaceCleanup` value `whole-reply-area` requires
persistent workspace. `written-bytes-only` is rejected; handlers keep the
stream raw-array API. Empty cleanup preserves
released bytes. See [cleanup contract and measured costs](PERSISTENT-WORKSPACE-COSTS.md)
for migration, lifecycle behavior, measurements and their limits.
Direct backend consumers use the package API; CLI integration is supplied by
the facade version they select.

## Runtime usage

Describe your interface in the javacard-rpc TOML IDL, generate the applet skeleton,
and implement the service methods. The facade repository documents IDL and CLI
usage. The root `src/main/java/io/jcrpc/server/AppletBase.java`, Gradle project
name, dependencies, Maven group/artifact names and Java package are preserved.

## Ordinary output writer API

The planned v0.4.0 generated Java API uses caller-owned output spans through
`dispatchTo(...)`. Byte-sequence and packed callbacks write into an output span
and return a produced length; scalar and void callbacks retain their return types.
This is an intentional source break with no compatibility shim. See the
[API, ownership, aliasing and migration contract](ORDINARY-OUTPUT-SPANS.md).
Generated ordinary local/span names are allocated against all request field
names, including later fields and occupied suffixes. Callback argument types and
order are unchanged; consumers may continue using fields such as output,
produced, result and payloadOffset.

## Tools and validation

| Tool | Command / purpose | Outputs |
| --- | --- | --- |
| Go/source only | make test-source: inspected generation/source checks with no JVM subprocesses | Console; capture logs under .temp/ |
| Go | go test ./... -count=1 -v: plugin parity and retained JavaCard regressions | Console; capture logs under .temp/ |
| JDK 17 / Classic API / Relux jCardSim | JCRPC_JCKIT_DIR=/path/jc305u4_kit JCRPC_JCARDSIM_JAR=/path/jcardsim-3.0.5.9-relux.1.jar go test ./codegen -run '^TestReviewerOrdinaryIdentifierRegression$' -count=1 -v: valid-name compilation and positional dispatch regression | Generated fixture/classes in test temporary directories; console |
| Go | go build ./...; go vet ./...: compile and lint backend | Go cache; console |
| Gradle wrapper | ./gradlew build --no-daemon --max-workers=2: build root runtime | build/libs/ |
| Make | make test, make build, make lint: the narrow combined entry points | Same outputs as above |
| Ant / ant-javacard / Java Card SDK | JCRPC_ANT_JAVACARD_JAR=/path/ant-javacard.jar JCRPC_JCKIT_DIR=/path/jc305u4_kit JAVA_HOME=/path/jdk11 PATH=/path/jdk11/bin:$PATH make test-cap | Ordinary writer, default and explicit whole-reply cleanup verified CAP inventories in test temporary directories |
| Relux jCardSim / JDK 17 | JCRPC_JCARDSIM_JAR=/path/jcardsim-3.0.5.9-relux.1.jar make test-simulator | Real simulator lifecycle, allocation, cost and intended-violation controls in test temporary directories |
| Go mutation runner | JCRPC_JCKIT_DIR=/path/jc305u4_kit JCRPC_JCARDSIM_JAR=/path/jcardsim-3.0.5.9-relux.1.jar go run ./.scripts/check-mutants --out .temp/mutants-01 | Disposable candidate fixtures, per-mutant logs and receipts.json |
| Git | git diff --check: whitespace validation | Console |

Ensure java and javac on PATH match the selected native lane. Relux jCardSim is
required for the CLEAR_ON_RESET digest variant; upstream 3.0.5.9 refuses that
construction. To also exercise the pinned consumer allocation test, set
JCRPC_ALLOCATION_IDL=testdata/bsim-auth.json and JCRPC_ALLOCATION_BASELINE to the
independent released Java source directory with package io.jcrpc.bsim. The root
runtime is tested through Simulator.transmitCommand and AppletBase.process.
Unset native toolchain variables explicitly skip optional native tests; required
Make lanes refuse missing configuration. A default Go pass alone does not claim
simulator or CAP coverage. Set TMPDIR under .temp/ when retaining native scratch.

The committed testdata matrix pins the JavaCard projection of all core v0.4.5
fixtures, namespaces and options. See codegen/testdata/README.md for provenance,
the 216-row cross product and explicit facade/physical-card bounds. Narrowing
mutants retain guards and use named behavioral tests; static allocation/cleanup
tokens are also attacked by behavior changes that preserve those tokens.

<!-- relux-ecosystem:start -->

## About Relux Works

This project is part of the open-source ecosystem of
[Relux Works](https://relux.works), an AI-native software development studio.
We build fixed-price MVPs, rescue vibe-coded apps, run local AI inference, and
train teams to work with coding agents. Much of the infrastructure behind that
work is open source.

- Full catalog: [relux.works/en/open-source](https://relux.works/en/open-source/)
- Agentic enablement: [agent harnesses & team training](https://relux.works/en/agentic-enablement/)
- Hire us the agent-native way: point your assistant at `https://api.relux.works/mcp`
- Contact: ivan@relux.works

<!-- relux-ecosystem:end -->

## License

See [LICENSE](LICENSE).
