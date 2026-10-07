.PHONY: test test-cap test-simulator build lint

test:
	go test ./... -count=1

build:
	go build ./...
	./gradlew build --no-daemon

lint:
	go vet ./...
	git diff --check

test-cap:
	@test -n "$(JCRPC_ANT_JAVACARD_JAR)" || { echo "JCRPC_ANT_JAVACARD_JAR is required" >&2; exit 2; }
	@test -n "$(JCRPC_JCKIT_DIR)" || { echo "JCRPC_JCKIT_DIR is required" >&2; exit 2; }
	@command -v ant >/dev/null 2>&1 || { echo "ant is required" >&2; exit 2; }
	go test ./codegen -run '^Test(GeneratedJavaStreamPackageConvertsToCAP|PersistentCleanupCAP)$$' -count=1 -v

test-simulator:
	@test -n "$(JCRPC_JCARDSIM_JAR)" || { echo "JCRPC_JCARDSIM_JAR is required" >&2; exit 2; }
	go test ./codegen -run 'TestRootAppletBaseRealSimulator|TestGeneratedWorkspaceRealSimulator|TestAllocationInstrumentRejectsNarrowingPlant|TestBSimAuthGeneratedAllocationPayload|TestPersistentCleanup(RealLifecycle|NarrowingMutants|Example)' -count=1 -v
