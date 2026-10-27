# v0.7.0 source candidate

This root release versions both the Go code-generation backend and the Java
runtime as 0.7.0. It includes the accepted compact stream-dispatch implementation:
immutable layout metadata is bound at construction, and each call supplies the
command's data and bounded buffer windows. This reduces repeated call arguments
without changing the declared wire protocol or adding per-command allocations.

Runtime coordinates are `io.jcrpc:javacard-rpc-server-javacard:0.7.0`.
The runtime jar is `build/libs/javacard-rpc-server-javacard-0.7.0.jar`, with matching
Implementation-Version metadata. This is a source build, not a Maven publication.
The root Go module consumes the published `pluginapi/v0.1.2` contract.

The focused wrong-CLA development control now widens admission only for A0 on
the already selected basic channel. B1 belongs to an unopened logical channel
in the strict simulator and is refused before the applet runtime, so it could
not witness a broken AppletBase CLA guard. The real runtime test separately
checks valid dispatch, wrong CLA without handler effects, unknown INS, unopened
channel refusal and successful recovery.

The ordinary Go/JVM/simulator suite and configured Classic CAP suite remain the
release checks. The focused runtime-cla-A0 mutation is a developer control;
full mutant sweeps are not landing gates. Physical-card behavior and performance
are not established by these host/converter checks.
