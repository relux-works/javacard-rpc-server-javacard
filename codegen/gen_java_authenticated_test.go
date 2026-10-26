package codegen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

// batchStoreSchema independently exercises two request-only storage operations:
// a 1537-byte batch summarized into a 29-byte record, and a 641-byte append
// returning an 11-byte position record. A 128-byte chunk leaves a one-byte tail
// at either bound. Neither operation signs data or handles credentials.
func batchStoreSchema() *Schema {
	stream := func(max int) *Message {
		return &Message{Fields: []Field{{Name: "packet", Type: FieldTypeStream, MaxLength: max, ChunkSize: 128}}}
	}
	return &Schema{
		Applet: Applet{Name: "BatchStore", Version: "1.0.0", AID: "F05566000101", CLA: 0xC0,
			StreamWorkspace: "persistent", StreamWorkspaceCleanup: StreamWorkspaceCleanupAuthenticatedInvalidate},
		Methods: map[string]*Method{
			"readState": {Name: "readState", INS: 0x03, Response: &Message{Fields: []Field{{Name: "version", Type: FieldTypeU8}}}},
			"summarizeBatch": {Name: "summarizeBatch", INS: 0x40, Request: stream(1537), Response: &Message{Fields: []Field{
				{Name: "prefix", Type: FieldTypeBytesFixed, FixedLength: 21}, {Name: "recordCount", Type: FieldTypeU32},
				{Name: "format", Type: FieldTypeU16}, {Name: "state", Type: FieldTypeU8}, {Name: "accepted", Type: FieldTypeBool}}}},
			"appendRecord": {Name: "appendRecord", INS: 0x68, Request: stream(641), Response: &Message{Fields: []Field{
				{Name: "offset", Type: FieldTypeU32}, {Name: "used", Type: FieldTypeU32}, {Name: "flags", Type: FieldTypeU16}, {Name: "state", Type: FieldTypeU8}}}},
		},
	}
}

func batchStoreResult(t *testing.T, memory StreamMemory) *JavaGenerationResult {
	t.Helper()
	r, err := GenerateJavaSkeletonWithOptions(batchStoreSchema(), "io.jcrpc.batchstore.server", JavaOptions{StreamMemory: memory})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The selector is admitted only with persistent storage and only by its exact
// spelling; every refusal returns no partial package. The positive control
// generates the same schema, so a validator that refuses everything fails.
func TestAuthenticatedInvalidateSelector(t *testing.T) {
	options := pluginapi.Options{Namespace: "io.jcrpc.batchstore.server", SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"}
	for _, mode := range []string{StreamWorkspaceCleanupAuthenticatedInvalidate, "Authenticated-invalidate", "authenticated-invalidate ", "authenticated"} {
		for _, storage := range []string{"", "transient", "persistent"} {
			s := batchStoreSchema()
			s.Applet.StreamWorkspace = storage
			s.Applet.StreamWorkspaceCleanup = mode
			files, err := (Plugin{}).Generate(s, options)
			valid := mode == StreamWorkspaceCleanupAuthenticatedInvalidate && storage == "persistent"
			if valid && (err != nil || len(files) == 0) {
				t.Fatalf("valid %q/%q refused: %v", storage, mode, err)
			}
			if !valid && (err == nil || files != nil) {
				t.Fatalf("invalid %q/%q admitted", storage, mode)
			}
		}
	}
}

// Every response-stream method is refused by name, so a streamed result can
// never be produced into NVM on an APDU that might still be refused. The real
// storage fixture names exactly its two response streams; removing them is the
// positive control that its remaining upload and ordinary methods generate.
func TestAuthenticatedInvalidateRefusesResponseStreams(t *testing.T) {
	s, err := ParseFile("testdata/sample-store.json")
	if err != nil {
		t.Fatal(err)
	}
	s.Applet.StreamWorkspace = "persistent"
	s.Applet.StreamWorkspaceCleanup = StreamWorkspaceCleanupAuthenticatedInvalidate
	options := pluginapi.Options{Namespace: "io.jcrpc.store", StreamMemory: "clear_on_reset", SimulatorDependency: "works.relux:jcardsim:3.0.5.9-relux.2"}
	files, err := (Plugin{}).Generate(s, options)
	if err == nil || files != nil {
		t.Fatalf("storage response streams admitted")
	}
	for _, want := range []string{"exchangePages (INS 0x12)", "enumeratePages (INS 0x42)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal does not name %s: %v", want, err)
		}
	}
	if strings.Count(err.Error(), "(INS 0x") != 2 {
		t.Fatalf("refusal names a request-only method: %v", err)
	}
	delete(s.Methods, "exchangePages")
	delete(s.Methods, "enumeratePages")
	if files, err := (Plugin{}).Generate(s, options); err != nil || len(files) == 0 {
		t.Fatalf("request-only storage fixture refused: %v", err)
	}
}

// Source contract of the new mode: the authority flag reaches the runtime from
// both production entries, and the runtime has no persistent wipe, reset
// marker or dirty frontier. Existing modes are frozen by the hash tests.
func TestAuthenticatedInvalidateSourceContract(t *testing.T) {
	if err := authenticatedSourceContract(batchStoreResult(t, StreamMemoryClearOnReset)); err != nil {
		t.Fatal(err)
	}
}

func authenticatedSourceContract(r *JavaGenerationResult) error {
	runtime, skeleton, adapter, endpoint := string(r.StreamRuntimeSource), string(r.SkeletonSource), string(r.StreamAPDUAdapterSource), string(r.StreamEndpointSource)
	for _, check := range []struct{ label, source, want string }{
		{"endpoint parameter", endpoint, "short callerWorkspaceCapacity,\n            boolean authenticated);"},
		{"runtime parameter", runtime, "short callerWorkspaceCapacity,\n            boolean authenticated) {"},
		{"runtime gate", runtime, "if (!authenticated) {\n            rejectWithoutClearing(SW_SECURITY_STATUS_NOT_SATISFIED);"},
		{"skeleton parameter", skeleton, "short callerWorkspaceCapacity,\n            boolean authenticated) {\n        short row = streamRow(ins);"},
		{"skeleton forwarding", skeleton, "callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity,\n                    authenticated);"},
		{"adapter parameter", adapter, "public boolean processIfStream(APDU apdu, boolean authenticated) {"},
		{"adapter forwarding", adapter, "(short) apduBuffer.length,\n                    authenticated);"},
		{"handler output span", runtime, "input, inputOffset, inputSize,\n                response, responseOffset, outputCapacity,"},
		{"output admission", runtime, "requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);"},
		{"admission predicate", runtime, "return buffer == javacard.framework.APDU.getCurrentAPDUBuffer();"},
	} {
		if strings.Count(check.source, check.want) != 1 {
			return fmt.Errorf("%s: %q appears %d times", check.label, check.want, strings.Count(check.source, check.want))
		}
	}
	for _, forbidden := range []string{"wipe(workspace)", "wipeWritten", "resetMarker", "IDX_DIRTY_END", "markWritten"} {
		if strings.Contains(runtime, forbidden) {
			return fmt.Errorf("runtime keeps persistent cleanup %q", forbidden)
		}
	}
	// Only the pre-auth gate refuses without invalidating; every refused
	// authenticated APDU invalidates the transient session.
	if n := strings.Count(runtime, "rejectWithoutClearing("); n != 2 {
		return fmt.Errorf("rejectWithoutClearing appears %d times, want the gate and its definition", n)
	}
	if !strings.Contains(runtime, "SCALAR_COUNT = (short) 17;") {
		return fmt.Errorf("scalar layout changed")
	}
	return nil
}

// The source contract is lint, not evidence: a mutant that keeps every token
// it searches for (the gate line is untouched) but routes an unauthenticated
// ABORT into the session must pass the text check and still be killed by the
// behavioral simulator suite.
func TestAuthenticatedInvalidateTokenPreservingMutant(t *testing.T) {
	jar := simulatorJar(t)
	r := batchStoreResult(t, StreamMemoryClearOnDeselect)
	anchor := "        if (!authenticated) {\n"
	source := string(r.StreamRuntimeSource)
	if strings.Count(source, anchor) != 1 {
		t.Fatal("mutation anchor")
	}
	r.StreamRuntimeSource = []byte(strings.Replace(source, anchor,
		"        if (!authenticated && operation == OP_ABORT) {\n            abort(ABORT_EXPLICIT);\n            return (short) 0;\n        }\n"+anchor, 1))
	if err := authenticatedSourceContract(r); err != nil {
		t.Fatalf("mutant does not preserve the searched tokens: %v", err)
	}
	output, err := runBatchStore(t, jar, r)
	if err == nil || !strings.Contains(output, "AssertionError: pre-auth abort") {
		t.Fatalf("token-preserving survivor: %v\n%s", err, output)
	}
	t.Log("killed token-preserving unauthenticated-abort by TestAuthenticatedInvalidateRealSimulator: pre-auth abort")
}

// --- jCardSim logical NVM ledger -------------------------------------------

var (
	// Every element store in generated code is one statement per line.
	nvmStoreLine = regexp.MustCompile(`(?m)^([ \t]*)(?:this\.)?(\w+)\[[^\n]*\] = [^\n]*;$`)
	// Any array element assignment, compound assignment or increment.
	nvmAnyStore = regexp.MustCompile(`\]\s*(=[^=]|\+=|-=|\*=|/=|\|=|&=|\^=|<<=|>>=|\+\+|--)`)
	nvmDigest   = "        streamSha256.doFinal(input, inputOffset, inputLength, output, outputOffset);"
)

// instrumentNvm prefixes every array element store and the one native digest
// writer in the generated sources with NvmLedger.store(target). Completeness is
// checked: a store the pattern cannot attribute, or any bulk-copy API, fails
// the test instead of silently escaping the ledger.
func instrumentNvm(t *testing.T, r *JavaGenerationResult) *JavaGenerationResult {
	t.Helper()
	result := *r
	for _, source := range []*[]byte{&result.TransportSource, &result.SkeletonSource, &result.StreamEndpointSource, &result.StreamRuntimeSource, &result.StreamAPDUAdapterSource} {
		text := string(*source)
		code := javaCodeOnly(text)
		if regexp.MustCompile(`Util\.array|arraycopy\(|\.doFinal\(|\.sign\(|\.generateData\(|\.getBytes\(`).MatchString(strings.Replace(code, strings.TrimSpace(nvmDigest), "", 1)) {
			t.Fatal("generated source calls a bulk writer outside the ledger")
		}
		want := len(nvmAnyStore.FindAllStringIndex(code, -1))
		got := 0
		text = nvmStoreLine.ReplaceAllStringFunc(text, func(line string) string {
			m := nvmStoreLine.FindStringSubmatch(line)
			got++
			return m[1] + "NvmLedger.store(" + m[2] + ");\n" + line
		})
		if got != want {
			t.Fatalf("ledger covers %d of %d array stores", got, want)
		}
		if strings.Contains(text, nvmDigest) {
			text = strings.Replace(text, nvmDigest, "        NvmLedger.store(output);\n"+nvmDigest, 1)
		}
		*source = []byte(text)
	}
	return &result
}

// javaCodeOnly drops line and block comments so prose never counts as code.
func javaCodeOnly(source string) string {
	source = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(source, "")
	return regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(source, "")
}

func runBatchStore(t *testing.T, jar string, r *JavaGenerationResult) (string, error) {
	t.Helper()
	return runRealJavaResult(t, jar, instrumentNvm(t, r), batchStoreApplet, batchStoreHarness, "BatchStoreHarness")
}

// Real Simulator.transmitCommand -> Applet.process -> (generated adapter
// processIfStream | caller-owned direct dispatchStreamTo over one APDU buffer)
// -> runtime.dispatch. Every refused APDU in the AC list is asserted to make 0
// logical persistent stores, each paired with an accepted control. Logical
// stores include same-value stores; JCRE journaling, native crypto state and
// physical EEPROM endurance are outside this ledger.
func TestAuthenticatedInvalidateRealSimulator(t *testing.T) {
	jar := simulatorJar(t)
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		t.Run(string(memory), func(t *testing.T) {
			output, err := runBatchStore(t, jar, batchStoreResult(t, memory))
			if err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
			t.Log(output)
		})
	}
}

// Instrument controls: a same-value 1 B persistent store planted on the
// refusal path must fail the zero gate by name; the same plant on a transient
// array must leave the suite green.
func TestAuthenticatedInvalidateLedgerControls(t *testing.T) {
	jar := simulatorJar(t)
	anchor := "    private void fail(short statusWord) {\n"
	for _, tc := range []struct {
		name, plant, killed string
	}{
		{"persistent-one-byte", "        workspace[0] = workspace[0];\n", "post-reset refusal wrote persistent"},
		// Classification is by array identity, not by the name in the source.
		{"aliased-persistent-one-byte", "        byte[] alias = workspace;\n        alias[0] = alias[0];\n", "post-reset refusal wrote persistent"},
		{"transient-one-byte", "        digestScratch[0] = digestScratch[0];\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := batchStoreResult(t, StreamMemoryClearOnDeselect)
			source := string(r.StreamRuntimeSource)
			if strings.Count(source, anchor) != 1 {
				t.Fatal("plant anchor")
			}
			r.StreamRuntimeSource = []byte(strings.Replace(source, anchor, anchor+tc.plant, 1))
			output, err := runBatchStore(t, jar, r)
			if tc.killed == "" {
				if err != nil {
					t.Fatalf("transient plant counted as NVM: %v\n%s", err, output)
				}
				return
			}
			if err == nil || !strings.Contains(output, "AssertionError: "+tc.killed) {
				t.Fatalf("persistent plant escaped the named gate: %v\n%s", err, output)
			}
			t.Logf("killed %s by %s", tc.name, tc.killed)
		})
	}
}

// Each mutant keeps its guard and admits exactly one member of the class the
// guard must reject. Only the named behavioral assertion counts as a kill.
func TestAuthenticatedInvalidateNarrowingMutants(t *testing.T) {
	jar := simulatorJar(t)
	for _, tc := range []struct {
		name      string
		edits     [][2]string
		assertion string
	}{
		{"auth-gate-admits-first-chunk", [][2]string{{"        if (!authenticated) {", "        if (!authenticated && !(operation == OP_WRITE_OR_INVOKE && p1 == 0)) {"}}, "pre-auth chunk staged"},
		{"auth-gate-admits-abort", [][2]string{{"        if (!authenticated) {", "        if (!authenticated && operation != OP_ABORT) {"}}, "pre-auth abort"},
		{"invalid-output-receipt", [][2]string{{
			"                callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);\n        if (produced < 0 || produced > outputCapacity ||\n                (scalars[IDX_EXACT_SHORT_RESPONSE_LENGTH] >= 0 &&",
			"                callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);\n        if (produced == (short) (outputCapacity + 1)) {\n            copy(response, responseOffset, workspace, (short) 0, outputCapacity);\n        }\n        if (produced < 0 || produced > outputCapacity ||\n                (scalars[IDX_EXACT_SHORT_RESPONSE_LENGTH] >= 0 &&"}}, "invalid handler output wrote persistent"},
		{"put-output-in-workspace", [][2]string{
			{"                response, responseOffset, outputCapacity,", "                scalars[IDX_ACTIVE_METHOD] == 2 ? workspace : response, scalars[IDX_ACTIVE_METHOD] == 2 ? (short) 0 : responseOffset, outputCapacity,"},
			{"        scalars[IDX_RESULT_LENGTH] = produced;\n        scalars[IDX_SHORT_RESULT_LENGTH] = produced;", "        if (scalars[IDX_ACTIVE_METHOD] == 2) {\n            copy(workspace, (short) 0, response, responseOffset, produced);\n        }\n        scalars[IDX_RESULT_LENGTH] = produced;\n        scalars[IDX_SHORT_RESULT_LENGTH] = produced;"},
		}, "put handler failure wrote persistent"},
		{"invalidate-wipes-tail-chunk", [][2]string{{"        // Never writes the persistent workspace; see the class contract.", "        if (scalars[IDX_STATE] == STATE_WRITING && scalars[IDX_LAST_CHUNK_LENGTH] == 9) {\n            workspace[scalars[IDX_LAST_CHUNK_OFFSET]] = (byte) 0;\n        }"}}, "refused changed duplicate wrote persistent"},
		{"empty-close-refusal-writes", [][2]string{{"        try {\n            validateRange(requestBuffer, requestOffset, requestLength);", "        try {\n            if (scalars[IDX_STATE] == STATE_EMPTY && operation == OP_CLOSE_WRITE) {\n                workspace[0] = workspace[0];\n            }\n            validateRange(requestBuffer, requestOffset, requestLength);"}}, "post-reset refusal wrote persistent"},
		{"begin-admits-one-streamed-result", [][2]string{{"                responseEnabled || !requestEnabled) {", "                (responseEnabled && responseLimit != 64) || !requestEnabled) {"}}, "streamed result admitted"},
		// Row-specific plants: one same-value persistent store on exactly one
		// refusal or invalidation path; every other path stays write-free.
		{"bad-close-digest-writes", [][2]string{{"        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {\n            fail(SW_INVALID_DATA);", "        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {\n            workspace[0] = workspace[0];\n            fail(SW_INVALID_DATA);"}}, "refused bad close digest wrote persistent"},
		{"abort-writes", [][2]string{{"                abort(ABORT_EXPLICIT);\n                return (short) 0;", "                workspace[0] = workspace[0];\n                abort(ABORT_EXPLICIT);\n                return (short) 0;"}}, "abort wrote persistent"},
		{"foreign-method-writes", [][2]string{{"                    // A refused authenticated APDU invalidates the live handle.\n                    fail(SW_WRONG_STATE);", "                    // A refused authenticated APDU invalidates the live handle.\n                    workspace[0] = workspace[0];\n                    fail(SW_WRONG_STATE);"}}, "refused foreign method wrote persistent"},
		// Output admission: the guard stays and admits exactly one persistent
		// member: one method, one span, or one array shape.
		{"admission-admits-summary-method", [][2]string{{"        if (!isNonPersistent(response) || !isNonPersistent(callerWorkspace)) {", "        if (scalars[IDX_ACTIVE_METHOD] != 1 && (!isNonPersistent(response) || !isNonPersistent(callerWorkspace))) {"}}, "persistent response admitted"},
		{"admission-skips-caller-workspace", [][2]string{{"        if (!isNonPersistent(response) || !isNonPersistent(callerWorkspace)) {", "        if (!isNonPersistent(response)) {"}}, "persistent caller workspace admitted"},
		{"predicate-admits-255-byte-array", [][2]string{{"            return buffer == javacard.framework.APDU.getCurrentAPDUBuffer();", "            return buffer == javacard.framework.APDU.getCurrentAPDUBuffer() || buffer.length == 255;"}}, "persistent response admitted"},
		{"admission-skips-receipt-retry", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_STATE] != STATE_SHORT_CLOSED) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent receipt retry admitted"},
		// Foreign refusal: invalidation kept for every method but one.
		{"foreign-write-keeps-summary-handle", [][2]string{{"                    // A refused authenticated APDU invalidates the live handle.\n                    fail(SW_WRONG_STATE);", "                    // A refused authenticated APDU invalidates the live handle.\n                    if (scalars[IDX_ACTIVE_METHOD] == 1) {\n                        rejectWithoutClearing(SW_WRONG_STATE);\n                    }\n                    fail(SW_WRONG_STATE);"}}, "foreign refusal retained live handle"},
		{"foreign-close-keeps-sign-handle", [][2]string{{"                    scalars[IDX_ACTIVE_METHOD] != methodId) {\n                fail(SW_WRONG_STATE);", "                    scalars[IDX_ACTIVE_METHOD] != methodId) {\n                if (scalars[IDX_STATE] != STATE_EMPTY && scalars[IDX_ACTIVE_METHOD] == 1) {\n                    rejectWithoutClearing(SW_WRONG_STATE);\n                }\n                fail(SW_WRONG_STATE);"}}, "foreign close retained live handle"},
		{"handler-failure-writes", [][2]string{{"            if (e != failure) {\n                clearAll();", "            if (e != failure) {\n                workspace[0] = workspace[0];\n                clearAll();"}}, "handler failure wrote persistent"},
		{"deselect-writes", [][2]string{{"    public void abort(byte reason) {\n", "    public void abort(byte reason) {\n        if (reason == ABORT_DESELECT) {\n            workspace[0] = workspace[0];\n        }\n"}}, "adapter: deselect wrote persistent"},
		{"out-of-order-retry-writes", [][2]string{{"                index != (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF)) {\n            fail(SW_INVALID_DATA);", "                index != (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF)) {\n            workspace[0] = workspace[0];\n            fail(SW_INVALID_DATA);"}}, "post-reset retry wrote persistent"},
		{"oversized-declaration-writes", [][2]string{{"                length > chunkSize || (index < count - 1 && length != chunkSize)) {\n            fail(SW_WRONG_LENGTH);", "                length > chunkSize || (index < count - 1 && length != chunkSize)) {\n            workspace[0] = workspace[0];\n            fail(SW_WRONG_LENGTH);"}}, "oversized declaration wrote persistent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := batchStoreResult(t, StreamMemoryClearOnDeselect)
			source := string(r.StreamRuntimeSource)
			for _, edit := range tc.edits {
				if strings.Count(source, edit[0]) != 1 {
					t.Fatalf("mutation anchor count %d: %q", strings.Count(source, edit[0]), edit[0])
				}
				source = strings.Replace(source, edit[0], edit[1], 1)
			}
			r.StreamRuntimeSource = []byte(source)
			output, err := runBatchStore(t, jar, r)
			if err == nil || !strings.Contains(output, "AssertionError: "+tc.assertion) {
				t.Fatalf("survivor (no named failure): %v\n%s", err, output)
			}
			t.Logf("killed %s by TestAuthenticatedInvalidateRealSimulator: %s", tc.name, tc.assertion)
		})
	}
}

// The generation-time refusal is narrowed to admit exactly enumeratePages;
// the named Go test must fail on the mutated module copy.
func TestAuthenticatedInvalidateGenerationNarrowingMutant(t *testing.T) {
	if testing.Short() {
		t.Skip("copies the module and runs go test")
	}
	root := t.TempDir()
	module, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		copyTestFile(t, filepath.Join(module, name), filepath.Join(root, name))
	}
	err = filepath.Walk(filepath.Join(module, "codegen"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(module, path)
		copyTestFile(t, path, filepath.Join(root, rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "codegen/internal/render/stream_authenticated.go")
	source, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	from, to := "if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" {", "if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" && method.INS != 0x42 {"
	if strings.Count(string(source), from) != 1 {
		t.Fatal("mutation anchor")
	}
	writeTestFile(t, target, []byte(strings.Replace(string(source), from, to, 1)))
	cmd := exec.Command("go", "test", "./codegen", "-run", "^TestAuthenticatedInvalidateRefusesResponseStreams$", "-count=1")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "refusal does not name enumeratePages") {
		t.Fatalf("survivor: %v\n%s", err, output)
	}
	t.Log("killed generation-admits-enumeratePages by TestAuthenticatedInvalidateRefusesResponseStreams")
}

func copyTestFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, to, b)
}

// Reachable generated array payload for the independent SampleStore fixture
// with its response streams removed, comparing two current-source selectors.
// The adapter's 255-byte transient I/O array is reported separately. These
// primitive payloads exclude physical object overhead and consumer arrays;
// they are not historical release or physical-card measurements.
func TestAuthenticatedInvalidateAllocationPayload(t *testing.T) {
	jar := simulatorJar(t)
	totals := map[string][2]int{}
	for _, mode := range []string{pluginapi.StreamWorkspaceCleanupWholeReplyArea, StreamWorkspaceCleanupAuthenticatedInvalidate} {
		s, err := ParseFile("testdata/sample-store.json")
		if err != nil {
			t.Fatal(err)
		}
		delete(s.Methods, "exchangePages")
		delete(s.Methods, "enumeratePages")
		s.Applet.StreamWorkspace = "persistent"
		s.Applet.StreamWorkspaceCleanup = mode
		r, err := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.store", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
		if err != nil {
			t.Fatal(err)
		}
		signatures := regexp.MustCompile(`protected abstract ([\s\S]*?);`).FindAllStringSubmatch(string(r.SkeletonSource), -1)
		var methods strings.Builder
		for _, signature := range signatures {
			body := "return (short)0;"
			if strings.HasPrefix(signature[1], "byte on") {
				body = "return (byte)0;"
			}
			fmt.Fprintf(&methods, "protected %s { %s }\n", signature[1], body)
		}
		fixture := strings.ReplaceAll(allocationApplet, "METHODS", methods.String())
		if mode == StreamWorkspaceCleanupAuthenticatedInvalidate {
			fixture = strings.Replace(fixture, "adapter.processIfStream(apdu);", "adapter.processIfStream(apdu, false);", 1)
		}
		output := runRealJava(t, jar, r, fixture, allocationHarness, "AllocationHarness")
		transient, persistent := 0, 0
		for _, line := range regexp.MustCompile(`(?m)^skeleton\.\S+: (transient|persistent) \S+ payload=(\d+) B`).FindAllStringSubmatch(output, -1) {
			var n int
			fmt.Sscan(line[2], &n)
			if line[1] == "transient" {
				transient += n
			} else {
				persistent += n
			}
		}
		if !strings.Contains(output, "adapter.ioScratch: transient byte[255] payload=255 B") {
			t.Fatalf("adapter I/O array not observed\n%s", output)
		}
		totals[mode] = [2]int{transient, persistent}
		t.Logf("%s: skeleton-reachable transient=%d B persistent=%d B (+ adapter transient 255 B)\n%s", mode, transient, persistent, output)
	}
	whole, auth := totals[pluginapi.StreamWorkspaceCleanupWholeReplyArea], totals[StreamWorkspaceCleanupAuthenticatedInvalidate]
	// Independent inventory: auth mode drops the 1 B reset marker and the 2 B
	// dirty frontier; the persistent workspace and tables are unchanged.
	if auth[0] != whole[0]-3 || auth[1] != whole[1] {
		t.Fatalf("payload delta: whole-reply-area %v, authenticated-invalidate %v", whole, auth)
	}
}

const batchStoreApplet = `package io.jcrpc.batchstore.server;
import javacard.framework.*;
public final class BatchStoreApplet extends Applet {
 static BatchStoreApplet installed;
 static boolean authenticated=true, direct=false;
 // 0 accept, 1 fail after full output, 2 return capacity+1, 3 fail before output
 static int control=0;
 // Direct route output span: 0 APDU buffer, 1 persistent response, 2 persistent caller workspace, 3 transient response
 static int output=0, handlerCalls=0;
 final Logic logic=new Logic();final BatchStoreStreamAPDUAdapter adapter=new BatchStoreStreamAPDUAdapter(logic);
 final byte[] noData=new byte[0];
 final byte[] persistentSpan=new byte[255];final byte[] transientSpan=JCSystem.makeTransientByteArray((short)255,JCSystem.CLEAR_ON_RESET);
 public static void install(byte[] b,short o,byte l){new BatchStoreApplet().register();}
 BatchStoreApplet(){installed=this;}
 public void deselect(){adapter.deselect();}
 public void process(APDU apdu){
  if(selectingApplet())return;
  byte[] buf=apdu.getBuffer();NvmLedger.apdu=buf;
  if(logic.isStreamInstruction(buf[ISO7816.OFFSET_INS])){
   if(!direct){adapter.processIfStream(apdu,authenticated);return;}
   // Caller-owned route: one APDU buffer is request, response and caller workspace.
   byte ins=buf[ISO7816.OFFSET_INS],p1=buf[ISO7816.OFFSET_P1],p2=buf[ISO7816.OFFSET_P2];
   short len=apdu.setIncomingAndReceive();
   for(short i=0;i<len;i++){NvmLedger.store(buf);buf[i]=buf[(short)(ISO7816.OFFSET_CDATA+i)];}
   byte[] resp=output==1?persistentSpan:output==3?transientSpan:buf;byte[] work=output==2?persistentSpan:buf;
   short out=logic.dispatchStreamTo(ins,p1,p2,buf,(short)0,len,resp,(short)0,(short)255,work,(short)0,(short)work.length,authenticated);
   if(out>0&&resp!=buf)for(short i=0;i<out;i++){NvmLedger.store(buf);buf[i]=resp[i];}
   if(out>0)apdu.setOutgoingAndSend((short)0,out);
   return;
  }
  short n=logic.dispatchTo(buf[ISO7816.OFFSET_INS],buf[ISO7816.OFFSET_P1],buf[ISO7816.OFFSET_P2],noData,(short)0,(short)0,buf,(short)0,(short)buf.length,buf,(short)0,(short)buf.length);
  apdu.setOutgoingAndSend((short)0,n);
 }
 static final class Logic extends BatchStoreSkeleton {
  Logic(){super(null);}
  protected byte onReadState(byte[] w,short wo,short wc){return 1;}
  protected short onSummarizeBatchStream(byte[] input,short io,short il,byte[] output,short oo,short oc,byte[] w,short wo,short wc){
   return result(input,io,il,output,oo,oc,w,wo,(short)29);
  }
  protected short onAppendRecordStream(byte[] input,short io,short il,byte[] output,short oo,short oc,byte[] w,short wo,short wc){
   return result(input,io,il,output,oo,oc,w,wo,(short)11);
  }
  private short result(byte[] input,short io,short il,byte[] output,short oo,short oc,byte[] w,short wo,short width){
   handlerCalls++;
   if(control==3)failStream((short)0x6A80);
   // Exercise overlapping caller scratch before producing the final output.
   for(short i=0;i<16;i++){NvmLedger.store(w);w[(short)(wo+i)]=(byte)0x5A;}
   // Encode declared fields, including a canonical true byte, once each.
   for(short i=0;i<width;i++){
    byte value=0;
    if(width==29){
     if(i<21)value=i<il?input[(short)(io+i)]:(byte)0;
     else if(i==23)value=(byte)(il>>8);
     else if(i==24)value=(byte)il;
     else if(i==26||i==27||i==28)value=1;
    }else{
     if(i==6)value=(byte)(il>>8);
     else if(i==7)value=(byte)il;
     else if(i==10)value=1;
    }
    NvmLedger.store(output);output[(short)(oo+i)]=value;
   }
   if(control==1)failStream((short)0x6985);
   return control==2?(short)(oc+1):width;
  }
 }
}
final class NvmLedger {
 static byte[] apdu;static int persistent,transientStores,apduStores;
 static void store(Object array){
  if(array==null)return;
  if(array==apdu){apduStores++;return;}
  if(JCSystem.isTransient(array)!=JCSystem.NOT_A_TRANSIENT_OBJECT){transientStores++;return;}
  persistent++;
 }
 static void reset(){persistent=transientStores=apduStores=0;}
}
`

const batchStoreHarness = `package io.jcrpc.batchstore.server;
import javacard.framework.*;
import com.licel.jcardsim.base.*;
import java.lang.reflect.*;
import java.util.*;
import java.security.MessageDigest;
public class BatchStoreHarness {
 static Simulator simulator;static AID aid,other;static byte[] workspace;static String route;
 static final byte[] EMPTY=new byte[0];
 public static void main(String[] args)throws Exception{
  // Checker control: canonical true passes; canonical false and E2 must fail
  // specifically as an accepted-success contract violation.
  byte[] fieldControl=result(new byte[40],29);checkSummaryFields(fieldControl,40);
  for(int invalid:new int[]{0,0xE2}){
   fieldControl[28]=(byte)invalid;
   try{checkSummaryFields(fieldControl,40);throw new AssertionError("summary checker admitted invalid success");}
   catch(AssertionError expected){if(!"summary accepted must be canonical true".equals(expected.getMessage()))throw expected;}
  }
  fieldControl[28]=1;checkSummaryFields(fieldControl,40);
  simulator=new Simulator();aid=new AID(new byte[]{(byte)0xF0,0x55,0x66,0,1,1},(short)0,(byte)6);other=new AID(new byte[]{(byte)0xF0,0x55,0x66,0,1,2},(short)0,(byte)6);
  simulator.installApplet(aid,BatchStoreApplet.class);simulator.installApplet(other,EmptyApplet.class);simulator.selectApplet(aid);
  Object session=field(BatchStoreApplet.installed.logic,"streamSession");workspace=(byte[])field(session,"workspace");
  // Ledger controls: the workspace is persistent, a transient array is not.
  NvmLedger.reset();NvmLedger.store(workspace);NvmLedger.store(JCSystem.makeTransientByteArray((short)1,JCSystem.CLEAR_ON_RESET));
  if(NvmLedger.persistent!=1||NvmLedger.transientStores!=1)throw new AssertionError("ledger classification control");
  for(boolean direct:new boolean[]{false,true}){BatchStoreApplet.direct=direct;route=direct?"direct":"adapter";scenario();if(direct)outputAdmission();}
  direct(session);
  System.out.println("authenticated-invalidate: pre-auth, accepted, refusal, reset and retained-data controls green on adapter and direct routes");
 }
 static void scenario()throws Exception{
  BatchStoreApplet.control=0;
  byte[] a=chunk(128,1),b=chunk(9,2),full=cat(a,b);
  // Pre-authentication: refused before any session or persistent effect.
  auth(false);
  expect(0x6982,0x40,0,2,a,0,"pre-auth chunk staged");
  expect(0x6982,0x41,0,0,close(full),0,"pre-auth close");
  expect(0x6982,0x45,0,0,EMPTY,0,"pre-auth abort");
  expect(0x6982,0x68,0,1,b,0,"pre-auth put staged");
  if(!Arrays.equals(new byte[]{1},send(0x03,0,0,EMPTY)))throw new AssertionError("ordinary method unreachable before authentication");
  // Accepted authenticated session; an unauthenticated interleave cannot touch it.
  auth(true);
  expect(0x9000,0x40,0,2,a,128,"accepted first chunk");
  auth(false);
  expect(0x6982,0x40,1,2,b,0,"pre-auth continuation staged");
  expect(0x6982,0x45,0,0,EMPTY,0,"unauthenticated abort reached session");
  auth(true);
  expect(0x9000,0x40,1,2,b,9,"accepted last chunk");
  expect(0x9000,0x40,1,2,b,0,"identical duplicate wrote");
  byte[] summary=expect(0x9000,0x41,0,0,close(full),29,"accepted close receipt");
  if(!Arrays.equals(summary,result(full,29)))throw new AssertionError("accepted summary result");
  if(!Arrays.equals(summary,expect(0x9000,0x41,0,0,close(full),0,"close retry wrote")))throw new AssertionError("close retry result");
  // Reset: transient handles vanish, nothing is wiped, retries are refused read-only.
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before reset");
  simulator.reset();simulator.selectApplet(aid);
  expect(0x6985,0x41,0,0,close(full),0,"post-reset refusal wrote persistent");
  expect(0x6A80,0x40,1,2,b,0,"post-reset retry wrote persistent");
  session(a,b,full,29);
  simulator.reset();simulator.selectApplet(aid);
  expect(0x6985,0x41,0,0,close(full),0,"stale receipt after reset");
  // ABORT is accepted and still writes nothing; the receipt loses its handle.
  session(a,b,full,29);
  expect(0x9000,0x45,0,0,EMPTY,0,"abort wrote persistent");
  expect(0x6985,0x41,0,0,close(full),0,"stale receipt after abort");
  if(!Arrays.equals(Arrays.copyOf(workspace,29),summary))throw new AssertionError("retained public receipt was erased");
  // Changed duplicate, then the 6A80 retry; a fresh session stays usable.
  expect(0x9000,0x40,0,2,a,128,"accepted first chunk again");
  expect(0x9000,0x40,1,2,b,9,"accepted tail before duplicate");
  byte[] changed=b.clone();changed[4]^=1;
  expect(0x6A80,0x40,1,2,changed,0,"refused changed duplicate wrote persistent");
  expect(0x6A80,0x40,1,2,b,0,"6A80 retry wrote persistent");
  session(a,b,full,29);
  // Bad CLOSE digest and length.
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before bad close");expect(0x9000,0x40,1,2,b,9,"accepted tail before bad close");
  byte[] wrong=close(full);wrong[33]^=1;
  expect(0x6A80,0x41,0,0,wrong,0,"refused bad close digest wrote persistent");
  expect(0x6985,0x41,0,0,close(full),0,"close after refused close wrote persistent");
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before short close");expect(0x9000,0x40,1,2,b,9,"accepted tail before short close");
  expect(0x6700,0x41,0,0,Arrays.copyOf(close(full),33),0,"refused close length wrote persistent");
  // Foreign method: refused with 0 B and the refusal invalidates the live
  // handle, so the old CLOSE and a chunk retry are refused; a fresh session works.
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before foreign");
  expect(0x9000,0x40,1,2,b,9,"accepted tail before foreign attack");
  expect(0x6985,0x68,0,1,b,0,"refused foreign method wrote persistent");
  expect(0x6985,0x41,0,0,close(full),0,"foreign refusal retained live handle");
  expect(0x6A80,0x40,1,2,b,0,"retry after foreign refusal wrote persistent");
  // A CLOSE for another method is the same foreign refusal.
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before foreign close");
  expect(0x9000,0x40,1,2,b,9,"accepted tail before foreign close");
  expect(0x6985,0x69,0,0,close(full),0,"refused foreign close wrote persistent");
  expect(0x6985,0x41,0,0,close(full),0,"foreign close retained live handle");
  if(!Arrays.equals(result(full,29),expect(0x9000,0x41,0,0,closeAfter(a,b,full),29,"fresh session after foreign refusal")))throw new AssertionError("fresh session after foreign refusal");
  // Handler failures: output is written, but only to the response span.
  BatchStoreApplet.control=1;
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before handler failure");expect(0x9000,0x40,1,2,b,9,"accepted tail before handler failure");
  int touched=0;
  expect(0x6985,0x41,0,0,close(full),0,"handler failure wrote persistent");
  touched=NvmLedger.apduStores+NvmLedger.transientStores;
  if(touched<29)throw new AssertionError("failing handler did not write its output");
  byte[] record=chunk(40,3);
  expect(0x9000,0x68,0,1,record,40,"accepted put chunk");
  expect(0x6985,0x69,0,0,close(record),0,"put handler failure wrote persistent");
  BatchStoreApplet.control=2;
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before invalid output");expect(0x9000,0x40,1,2,b,9,"accepted tail before invalid output");
  expect(0x6700,0x41,0,0,close(full),0,"invalid handler output wrote persistent");
  BatchStoreApplet.control=3;
  expect(0x9000,0x68,0,1,record,40,"accepted put chunk before refusal");
  expect(0x6A80,0x69,0,0,close(record),0,"handler refusal wrote persistent");
  BatchStoreApplet.control=0;
  expect(0x9000,0x68,0,1,record,40,"accepted put chunk after refusals");
  if(!Arrays.equals(result(record,11),expect(0x9000,0x69,0,0,close(record),11,"accepted put receipt")))throw new AssertionError("put result");
  // Deselect invalidates without writing.
  expect(0x9000,0x40,0,2,a,128,"accepted chunk before deselect");
  NvmLedger.reset();simulator.selectApplet(other);simulator.selectApplet(aid);
  if(NvmLedger.persistent!=0)throw new AssertionError(route+": deselect wrote persistent");
  expect(0x6985,0x41,0,0,close(full),0,"close after deselect wrote persistent");
  // Declared bound: 1537 B accepted in thirteen chunks; one more packet is refused.
  byte[] max=chunk(1537,4);
  for(int i=0;i<13;i++){byte[] part=Arrays.copyOfRange(max,i*128,Math.min(1537,(i+1)*128));expect(0x9000,0x40,i,13,part,part.length,"accepted bounded chunk");}
  if(!Arrays.equals(result(max,29),expect(0x9000,0x41,0,0,close(max),29,"accepted bounded close")))throw new AssertionError("bounded result");
  // Regression: the former XOR put E2 at bool offset 28 for E3 input.
  // Nearby 00/01 inputs previously yielded canonical true/false by accident.
  for(int sourceByte:new int[]{0,1,0xE3}){
   byte[] vector=chunk(40,4);vector[28]=(byte)sourceByte;
   expect(0x9000,0x40,0,1,vector,40,"boolean witness accepted chunk");
   byte[] response=expect(0x9000,0x41,0,0,close(vector),29,"boolean witness accepted close");
   if(!Arrays.equals(result(vector,29),response))throw new AssertionError("boolean witness prefix/fields");
  }
  expect(0x6700,0x40,0,14,a,0,"oversized declaration wrote persistent");
 }
 // Installation-configured runtime: a streamed result is refused in begin
 // before any command effect; the nearby short-result control remains usable.
 static BatchStoreStreamEndpoint configured(Object session,boolean response)throws Exception{
  return new BatchStoreBoundedStreamRuntime((byte[])field(session,"workspace"),(byte[])field(session,"digestScratch"),
   (short[])field(session,"scalars"),(Object[])field(session,"handlerSlot"),BatchStoreApplet.installed.logic,
   BatchStoreApplet.installed.logic,new byte[]{(byte)(response?3:2)},
   new short[]{64,32,(short)(response?64:0),(short)(response?32:0),(short)(response?-1:29)});
 }
 static void direct(Object session)throws Exception{
  BatchStoreStreamEndpoint endpoint=configured(session,true);byte[] io=new byte[255];
  NvmLedger.reset();
  try{endpoint.dispatch((byte)1,BatchStoreStreamEndpoint.OP_WRITE_OR_INVOKE,(byte)0,(byte)1,io,(short)0,(short)4,io,(short)0,(short)255,io,(short)0,(short)255,true);throw new AssertionError("streamed result admitted");}
  catch(BatchStoreStreamEndpoint.StreamStatusWordException e){if(e.getStatusWord()!=(short)0x6A84)throw new AssertionError("streamed result admitted: "+Integer.toHexString(e.getStatusWord()&65535));}
  if(NvmLedger.persistent!=0)throw new AssertionError("streamed result refusal wrote persistent");
  endpoint=configured(session,false);NvmLedger.reset();
  try{endpoint.dispatch((byte)1,BatchStoreStreamEndpoint.OP_WRITE_OR_INVOKE,(byte)0,(byte)1,io,(short)0,(short)4,io,(short)0,(short)255,io,(short)0,(short)255,true);}
  catch(BatchStoreStreamEndpoint.StreamStatusWordException e){throw new AssertionError("short result control refused: "+Integer.toHexString(e.getStatusWord()&65535));}
  if(NvmLedger.persistent!=4)throw new AssertionError("short result control stored "+NvmLedger.persistent);
  endpoint.abort(BatchStoreStreamEndpoint.ABORT_EXPLICIT);
 }
 // Direct route: the caller chooses the output and caller-workspace arrays.
 // A persistent span is refused on CLOSE before the handler or the receipt
 // copy runs, and the refusal invalidates the session; transient and APDU
 // spans are the accepted controls (the APDU span is the main scenario).
 static void outputAdmission()throws Exception{
  byte[] a=chunk(128,1),b=chunk(9,2),full=cat(a,b);
  for(int[] c:new int[][]{{1,1},{1,0},{2,1},{2,0}}){
   String kind=c[0]==1?"persistent response":"persistent caller workspace";
   BatchStoreApplet.output=0;BatchStoreApplet.control=c[1];
   expect(0x9000,0x40,0,2,a,128,"accepted chunk before "+kind);expect(0x9000,0x40,1,2,b,9,"accepted tail before "+kind);
   int calls=BatchStoreApplet.handlerCalls;
   BatchStoreApplet.output=c[0];
   expect(0x6985,0x41,0,0,close(full),0,kind+" admitted");
   if(BatchStoreApplet.handlerCalls!=calls)throw new AssertionError(kind+" admitted: handler ran");
   BatchStoreApplet.output=0;BatchStoreApplet.control=0;
   expect(0x6985,0x41,0,0,close(full),0,kind+" refusal retained live handle");
  }
  // Accepted receipt, then its retry into a persistent response is refused.
  BatchStoreApplet.output=0;
  byte[] summary=expect(0x9000,0x41,0,0,closeAfter(a,b,full),29,"accepted close before receipt retry");
  BatchStoreApplet.output=1;
  expect(0x6985,0x41,0,0,close(full),0,"persistent receipt retry admitted");
  BatchStoreApplet.output=0;
  expect(0x6985,0x41,0,0,close(full),0,"receipt retry refusal retained live handle");
  // Transient response control: accepted, same result, receipt retry 0 B.
  BatchStoreApplet.output=3;
  if(!Arrays.equals(summary,expect(0x9000,0x41,0,0,closeAfter(a,b,full),29,"transient response close")))throw new AssertionError("transient response result");
  if(!Arrays.equals(summary,expect(0x9000,0x41,0,0,close(full),0,"transient response retry wrote")))throw new AssertionError("transient response retry result");
  BatchStoreApplet.output=0;
  expect(0x9000,0x45,0,0,EMPTY,0,"abort after transient control");
 }
 static byte[] closeAfter(byte[] a,byte[] b,byte[] full){expect(0x9000,0x40,0,2,a,128,"fresh session first chunk");expect(0x9000,0x40,1,2,b,9,"fresh session tail");return close(full);}
 static void session(byte[] a,byte[] b,byte[] full,int width){
  expect(0x9000,0x40,0,2,a,128,"fresh session first chunk");expect(0x9000,0x40,1,2,b,9,"fresh session tail");
  if(!Arrays.equals(result(full,width),expect(0x9000,0x41,0,0,close(full),width,"fresh session close")))throw new AssertionError("fresh session result");
 }
 static void auth(boolean value){BatchStoreApplet.authenticated=value;}
 static byte[] expect(int sw,int ins,int p1,int p2,byte[] data,int persistent,String label){
  NvmLedger.reset();byte[] out=EMPTY;int got;
  try{out=send(ins,p1,p2,data);got=0x9000;}catch(ISOException e){got=e.getReason()&65535;}
  if(got!=sw)throw new AssertionError(label+" ["+route+"]: status "+Integer.toHexString(got)+" expected "+Integer.toHexString(sw));
  if(NvmLedger.persistent!=persistent)throw new AssertionError(label+" ["+route+"]: persistent stores "+NvmLedger.persistent+" expected "+persistent);
  if(sw==0x9000&&ins==0x41)checkSummaryFields(out,((data[0]&255)<<8)|(data[1]&255));
  if(sw==0x9000&&ins==0x69){
   if(out.length!=11||u32(out,0)!=0||u32(out,4)!=(((data[0]&255)<<8)|(data[1]&255))||
      out[8]!=0||out[9]!=0||out[10]!=1)throw new AssertionError("append typed fields");
  }
  return out;
 }
 // Decode integers independently of the handler's per-byte encoder.
 static long u32(byte[] data,int offset){return java.nio.ByteBuffer.wrap(data,offset,4).getInt()&0xFFFFFFFFL;}
 static void checkSummaryFields(byte[] response,int length){
  if(response.length!=29||u32(response,21)!=length||
     java.nio.ByteBuffer.wrap(response,25,2).getShort()!=1||response[27]!=1)
   throw new AssertionError("summary typed integer fields");
  if(response[28]!=1)throw new AssertionError("summary accepted must be canonical true");
 }
 static byte[] result(byte[] input,int width){
  java.nio.ByteBuffer result=java.nio.ByteBuffer.allocate(width);
  if(width==29){result.put(Arrays.copyOf(input,21));result.putInt(input.length).putShort((short)1).put((byte)1).put((byte)1);}
  else{result.putInt(0).putInt(input.length).putShort((short)0).put((byte)1);}
  return result.array();
 }
 static byte[] chunk(int n,int seed){byte[] r=new byte[n];for(int i=0;i<n;i++)r[i]=(byte)(seed*31+i*7);return r;}
 static byte[] cat(byte[] x,byte[] y){byte[] r=Arrays.copyOf(x,x.length+y.length);System.arraycopy(y,0,r,x.length,y.length);return r;}
 // The fixture selects the basic channel only. 80 is the generated C0 class's
 // first-coding form; C0 itself selects unopened channel 4 in a channel-aware
 // simulator and is refused before the applet's authentication gate runs.
 static byte[] send(int ins,int p1,int p2,byte[] data){byte[] a=new byte[data.length==0?4:data.length+5];a[0]=(byte)0x80;a[1]=(byte)ins;a[2]=(byte)p1;a[3]=(byte)p2;if(data.length>0){a[4]=(byte)data.length;System.arraycopy(data,0,a,5,data.length);}byte[] r=simulator.transmitCommand(a);int n=r.length;short sw=(short)(((r[n-2]&255)<<8)|(r[n-1]&255));if(sw!=(short)0x9000)ISOException.throwIt(sw);return Arrays.copyOf(r,n-2);}
 static byte[] close(byte[] data){try{byte[] r=new byte[34];r[0]=(byte)(data.length>>8);r[1]=(byte)data.length;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(data),0,r,2,32);return r;}catch(Exception e){throw new RuntimeException(e);}}
 static Object field(Object x,String n)throws Exception{Class<?> c=x.getClass();while(c!=null){try{Field f=c.getDeclaredField(n);f.setAccessible(true);return f.get(x);}catch(NoSuchFieldException e){c=c.getSuperclass();}}throw new NoSuchFieldException(n);}
 public static class EmptyApplet extends Applet{public static void install(byte[] b,short o,byte l){new EmptyApplet().register();}public void process(APDU a){}}
}
`

// The converter, not javac, decides Java Card Classic compatibility: both
// lifecycle choices of the new mode convert and verify with the pinned kit.
// Conversion proves no target RAM, NVM or physical-card behavior.
func TestAuthenticatedInvalidateClassicCAP(t *testing.T) {
	ant, err := exec.LookPath("ant")
	if err != nil {
		t.Fatal(err)
	}
	jar, kit := os.Getenv("JCRPC_ANT_JAVACARD_JAR"), os.Getenv("JCRPC_JCKIT_DIR")
	if jar == "" || kit == "" {
		t.Skip("set CAP toolchain variables")
	}
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		t.Run(string(memory), func(t *testing.T) {
			r := batchStoreResult(t, memory)
			root := t.TempDir()
			sourceDir := filepath.Join(root, "src", "io", "jcrpc", "batchstore", "server")
			for name, source := range map[string][]byte{
				r.TransportName + ".java": r.TransportSource, r.SkeletonName + ".java": r.SkeletonSource,
				r.StreamEndpointName + ".java": r.StreamEndpointSource, r.StreamRuntimeName + ".java": r.StreamRuntimeSource,
				r.StreamAPDUAdapterName + ".java": r.StreamAPDUAdapterSource, "BatchStoreApplet.java": []byte(batchStoreCAPApplet),
			} {
				writeTestFile(t, filepath.Join(sourceDir, name), source)
			}
			buildXML := fmt.Sprintf(`<project name="authenticated-invalidate-cap" default="cap">
    <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/>
    <target name="cap">
        <javacard>
            <cap jckit="%s" sources="%s" package="io.jcrpc.batchstore.server" aid="F055660001" version="1.0" ints="true" output="%s">
                <applet class="io.jcrpc.batchstore.server.BatchStoreApplet" aid="F05566000101"/>
            </cap>
        </javacard>
    </target>
</project>
`, filepath.ToSlash(jar), filepath.ToSlash(kit), filepath.ToSlash(filepath.Join(root, "src")), filepath.ToSlash(filepath.Join(root, "batchstore.cap")))
			writeTestFile(t, filepath.Join(root, "build.xml"), []byte(buildXML))
			command := exec.Command(ant, "-f", filepath.Join(root, "build.xml"), "cap")
			command.Dir = root
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("CAP conversion failed: %v\n%s", err, output)
			}
			info, err := os.Stat(filepath.Join(root, "batchstore.cap"))
			if err != nil || info.Size() == 0 {
				t.Fatalf("CAP output missing: %v", err)
			}
			t.Logf("verified CAP ZIP=%d B\n%s", info.Size(), output)
		})
	}
}

const batchStoreCAPApplet = `package io.jcrpc.batchstore.server;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;

public final class BatchStoreApplet extends Applet {
    private final Logic logic;
    private final BatchStoreStreamAPDUAdapter streams;
    private final byte[] noData;
    private boolean authenticated;

    public static void install(byte[] installData, short offset, byte length) {
        new BatchStoreApplet().register();
    }

    BatchStoreApplet() {
        logic = new Logic();
        streams = new BatchStoreStreamAPDUAdapter(logic);
        noData = new byte[0];
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_INS] == (byte) 0x68) {
            // Caller-owned route: one APDU buffer for request, response and scratch.
            byte p1 = buffer[ISO7816.OFFSET_P1];
            byte p2 = buffer[ISO7816.OFFSET_P2];
            short length = apdu.setIncomingAndReceive();
            for (short i = 0; i < length; i++) {
                buffer[i] = buffer[(short) (ISO7816.OFFSET_CDATA + i)];
            }
            short produced = logic.dispatchStreamTo((byte) 0x68, p1, p2, buffer, (short) 0, length,
                    buffer, (short) 0, (short) 255, buffer, (short) 0, (short) buffer.length, authenticated);
            if (produced > 0) apdu.setOutgoingAndSend((short) 0, produced);
            return;
        }
        if (streams.processIfStream(apdu, authenticated)) return;
        short produced = logic.dispatchTo(buffer[ISO7816.OFFSET_INS], buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2],
                noData, (short) 0, (short) 0, buffer, (short) 0, (short) buffer.length, buffer, (short) 0, (short) buffer.length);
        apdu.setOutgoingAndSend((short) 0, produced);
    }

    public void deselect() {
        streams.deselect();
    }

    private static final class Logic extends BatchStoreSkeleton {
        Logic() { super(null); }

        protected byte onReadState(byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) { return (byte) 1; }

        protected short onSummarizeBatchStream(byte[] input, short inputOffset, short inputLength,
                byte[] output, short outputOffset, short outputCapacity, byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            return fill(input, inputOffset, inputLength, output, outputOffset, (short) 29);
        }

        protected short onAppendRecordStream(byte[] input, short inputOffset, short inputLength,
                byte[] output, short outputOffset, short outputCapacity, byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            return fill(input, inputOffset, inputLength, output, outputOffset, (short) 11);
        }

        private short fill(byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset, short width) {
            for (short i = 0; i < width; i++) {
                byte value = 0;
                if (width == 29) {
                    if (i < 21) value = i < inputLength ? input[(short) (inputOffset + i)] : (byte) 0;
                    else if (i == 23) value = (byte) (inputLength >> 8);
                    else if (i == 24) value = (byte) inputLength;
                    else if (i == 26 || i == 27 || i == 28) value = 1;
                } else {
                    if (i == 6) value = (byte) (inputLength >> 8);
                    else if (i == 7) value = (byte) inputLength;
                    else if (i == 10) value = 1;
                }
                output[(short) (outputOffset + i)] = value;
            }
            return width;
        }
    }
}
`

// Review rev1 regression witnesses, kept under the reviewer's names. The
// reviewer's probes edited the fixture; their assertions now live in the
// shared harness, so each test pins its exact assertion lines and then drives
// the real simulator suite through Simulator.transmitCommand -> Applet.process
// -> dispatchStreamTo / processIfStream -> runtime.dispatch.
func runReviewerWitness(t *testing.T, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if strings.Count(batchStoreHarness, line) != 1 {
			t.Fatalf("witness assertion missing from the harness: %s", line)
		}
	}
	jar := simulatorJar(t)
	output, err := runBatchStore(t, jar, batchStoreResult(t, StreamMemoryClearOnReset))
	if err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
}

// A persistent response array on the direct route is refused before the
// failing handler runs: 6985, 0 persistent stores, handler not invoked, and
// the session is invalidated. Transient and APDU responses stay accepted.
func TestReviewerPersistentResponseRefusal(t *testing.T) {
	runReviewerWitness(t,
		`expect(0x6985,0x41,0,0,close(full),0,kind+" admitted");`,
		`if(BatchStoreApplet.handlerCalls!=calls)throw new AssertionError(kind+" admitted: handler ran");`,
		`expect(0x6985,0x41,0,0,close(full),0,"persistent receipt retry admitted");`,
		`expect(0x9000,0x41,0,0,closeAfter(a,b,full),29,"transient response close")`)
}

// A foreign-method refusal invalidates the live handle: the old valid CLOSE
// is refused 6985 (rev1 returned 9000) and a chunk retry is refused 6A80,
// both with 0 persistent stores.
func TestReviewerForeignMethodInvalidates(t *testing.T) {
	runReviewerWitness(t,
		`expect(0x9000,0x40,1,2,b,9,"accepted tail before foreign attack");`,
		`expect(0x6985,0x68,0,1,b,0,"refused foreign method wrote persistent");`,
		`expect(0x6985,0x41,0,0,close(full),0,"foreign refusal retained live handle");`,
		`expect(0x6A80,0x40,1,2,b,0,"retry after foreign refusal wrote persistent");`)
}
