# v0.5.0 source candidate

This breaking minor appends a caller-owned workspace array/offset/capacity to all
ordinary and streamed generated dispatch/callback APIs. Auth Route B can now
receive the legal entry workspace independently of exact reply spans and owned
stream bulk storage. Regenerate subclasses and adapters using
[the copyable migration contract](CALLER-WORKSPACE.md); no old-signature shim is
provided. Scalar/void returns, IDL/wire values and fixed outputs remain intact.

Borrowed scratch is checked before callback/session effects; invalid stream
scratch preserves pending state for a valid retry. Scratch/input/output references
remain command-local. Trusted handlers own alias ordering, phase minima and
output liveness. The generic runtime accepts empty valid windows and has no
Auth-specific size policy. A 133-byte physical buffer cannot satisfy 196/260
phase minima or whole 177/190-byte replies.

The root Go module's next release tag is v0.5.0. Root runtime metadata is 0.5.0;
coordinates remain io.jcrpc:javacard-rpc-server-javacard:0.5.0. Gradle produces
build/libs/javacard-rpc-server-javacard-0.5.0.jar with Implementation-Version 0.5.0.
This is a source build coordinate, not a Maven repository publication claim.
The only released Go dependency remains pluginapi v0.1.1.

The source producer qualifies JVM behavior, negative/narrowing/token-preserving
controls, actual simulator/APDU, allocation/cleanup/replay regressions and real
Classic 3.0.5u4 CAP variants. Classic conversion still requires optional int
support. Historical v0.4.5 and v0.4.0 evidence stays historical; the maintained
216-row API projection separately freezes all changed generated files.

Independent source acceptance, canonical signed branch/PR/review/green-check
landing, root signed v0.5.0 tag and actual release are still release-owner work.
This source candidate makes no publication, physical installation or real Auth
consumer acceptance claim. Consumers qualify their real command chains against
the actual published target/facade pins under their own JVM authority.
