package codegen

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

// modeStoreSchema exercises page preview, authenticated page description,
// incremental offset inspection and a read-only circular storage window.
// Offset requests are raw big-endian u16 relative seeks (FFFF is reserved),
// without a tagged transcript, certificate or cryptographic proof record.
func modeStoreSchema() *Schema {
	stream := func(max int) *Message {
		return &Message{Fields: []Field{{Name: "packet", Type: FieldTypeStream, MaxLength: max, ChunkSize: 192}}}
	}
	return &Schema{
		Applet: Applet{Name: "ModeStore", Version: "1.0.0", AID: "F00000010401", CLA: 0xB0,
			StreamWorkspace: "persistent", StreamWorkspaceCleanup: StreamWorkspaceCleanupAuthenticatedInvalidate},
		Methods: map[string]*Method{
			"getVersion": {Name: "getVersion", INS: 0x01, Response: &Message{Fields: []Field{{Name: "version", Type: FieldTypeU8}}}},
			"exchangePage": {Name: "exchangePage", INS: 0x13, StreamMode: StreamModePublicInvalidate,
				Request: stream(1472), Response: stream(1472)},
			"inspectOffsets": {Name: "inspectOffsets", INS: 0x23, StreamMode: StreamModeChunked, Request: stream(1024), Response: &Message{Fields: []Field{
				{Name: "wordCount", Type: FieldTypeU16}, {Name: "cursor", Type: FieldTypeU16}, {Name: "wordXor", Type: FieldTypeU16}}}},
			"describePage": {Name: "describePage", INS: 0x33, Request: stream(1024), Response: &Message{Fields: []Field{
				{Name: "length", Type: FieldTypeU32}, {Name: "digest", Type: FieldTypeBytesFixed, FixedLength: 32}}}},
			"readWindow": {Name: "readWindow", INS: 0x43, StreamMode: StreamModeChunked,
				Request: stream(352), Response: stream(1280)},
			"describePublicPage": {Name: "describePublicPage", INS: 0x53, StreamMode: StreamModePublicInvalidate,
				Request: stream(1024), Response: &Message{Fields: []Field{
					{Name: "length", Type: FieldTypeU32}, {Name: "digest", Type: FieldTypeBytesFixed, FixedLength: 32}}}},
		},
	}
}

func modeStoreResult(t *testing.T, memory StreamMemory) *JavaGenerationResult {
	t.Helper()
	r, err := GenerateJavaSkeletonWithOptions(modeStoreSchema(), "io.jcrpc.modestore.server", JavaOptions{StreamMemory: memory})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runModeStore(t *testing.T, jar string, r *JavaGenerationResult) (string, error) {
	t.Helper()
	return runRealJavaResult(t, jar, instrumentNvm(t, r), readTestdata(t, "ModeStoreApplet.java"),
		readTestdata(t, "ModeStoreHarness.java"), "ModeStoreHarness")
}

// Real Simulator.transmitCommand -> ModeStoreApplet.process -> (generated
// adapter processIfStream | direct dispatchStreamTo over one APDU
// buffer) -> runtime.dispatch, on both lifecycle choices. Every APDU asserts
// its status word and its logical persistent store count: chunked APDUs make
// 0 B on success and refusal, public APDUs make exactly the accepted chunk
// length or 0 B, and each refusal is followed by a dead-stream check and a
// nearby accepted control. Logical stores include same-value stores; JCRE
// journaling, MessageDigest internal state and physical EEPROM are
// outside this ledger.
func TestStreamModesRealSimulator(t *testing.T) {
	jar := simulatorJar(t)
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		t.Run(string(memory), func(t *testing.T) {
			output, err := runModeStore(t, jar, modeStoreResult(t, memory))
			if err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
			t.Log(output)
		})
	}
}

// sampleWithModes selects public-invalidate for page exchange and chunked
// processing for the other three synthetic storage streams.
func sampleWithModes(t *testing.T) *Schema {
	t.Helper()
	s, err := ParseFile("testdata/sample-store.json")
	if err != nil {
		t.Fatal(err)
	}
	s.Applet.StreamWorkspace = "persistent"
	s.Applet.StreamWorkspaceCleanup = StreamWorkspaceCleanupAuthenticatedInvalidate
	for name, mode := range map[string]string{
		"exchangePages":  StreamModePublicInvalidate,
		"appendPages":    StreamModeChunked,
		"summarizePages": StreamModeChunked,
		"enumeratePages": StreamModeChunked,
	} {
		if s.Methods[name] == nil {
			t.Fatalf("storage fixture lacks %s", name)
		}
		s.Methods[name].StreamMode = mode
	}
	return s
}

// Generation refuses every misplaced or unknown mode by name and returns no
// partial package; the mode fixture and independent storage fixture with its modes
// are the positive controls, so a validator that refuses everything fails.
func TestStreamModeValidation(t *testing.T) {
	options := pluginapi.Options{Namespace: "io.jcrpc.modestore.server", SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"}
	for _, tc := range []struct {
		name   string
		mutate func(*Schema)
		want   string
	}{
		{"unknown-mode", func(s *Schema) { s.Methods["inspectOffsets"].StreamMode = "Chunked" }, `inspectOffsets (INS 0x23): unknown stream mode "Chunked"`},
		{"padded-mode", func(s *Schema) { s.Methods["inspectOffsets"].StreamMode = "chunked " }, `unknown stream mode "chunked "`},
		{"ordinary-method", func(s *Schema) { s.Methods["getVersion"].StreamMode = StreamModeChunked }, `getVersion (INS 0x01): stream mode "chunked" applies only to a streamed method`},
		{"whole-reply-area", func(s *Schema) { s.Applet.StreamWorkspaceCleanup = pluginapi.StreamWorkspaceCleanupWholeReplyArea }, `requires stream_workspace_cleanup "authenticated-invalidate"`},
		{"released-default", func(s *Schema) { s.Applet.StreamWorkspaceCleanup = "" }, `requires stream_workspace_cleanup "authenticated-invalidate"`},
		{"chunked-response-only", func(s *Schema) {
			s.Methods["inspectOffsets"].Request = nil
			s.Methods["inspectOffsets"].Response = s.Methods["readWindow"].Response
		}, `inspectOffsets (INS 0x23): stream mode "chunked" requires a request stream`},
		{"response-only-public", func(s *Schema) {
			s.Methods["inspectOffsets"].Request = nil
			s.Methods["inspectOffsets"].Response = s.Methods["readWindow"].Response
			s.Methods["inspectOffsets"].StreamMode = StreamModePublicInvalidate
		}, `inspectOffsets (INS 0x23): stream mode "public-invalidate" requires a request stream`},
		{"authenticated-streamed-result", func(s *Schema) { s.Methods["readWindow"].StreamMode = "" }, `readWindow (INS 0x43)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := modeStoreSchema()
			tc.mutate(s)
			files, err := (Plugin{}).Generate(s, options)
			if err == nil || files != nil {
				t.Fatalf("invalid stream modes admitted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal does not name %q: %v", tc.want, err)
			}
		})
	}
	if files, err := (Plugin{}).Generate(modeStoreSchema(), options); err != nil || len(files) != 7 {
		t.Fatalf("ModeStore fixture refused: %d %v", len(files), err)
	}
	auth := pluginapi.Options{Namespace: "io.jcrpc.store", StreamMemory: "clear_on_reset", SimulatorDependency: "works.relux:jcardsim:3.0.5.9-relux.3"}
	files, err := (Plugin{}).Generate(sampleWithModes(t), auth)
	if err != nil || len(files) != 7 {
		t.Fatalf("storage fixture with modes refused: %v", err)
	}
	// Without a mode on its streamed-result method the storage fixture is refused again.
	s := sampleWithModes(t)
	s.Methods["enumeratePages"].StreamMode = ""
	if _, err := (Plugin{}).Generate(s, auth); err == nil || !strings.Contains(err.Error(), "enumeratePages (INS 0x42)") {
		t.Fatalf("authenticated streamed result admitted: %v", err)
	}
}

// Schemas without a stream mode match the current-source BatchStore and
// SampleStore projections. These independently authored fixtures do not establish
// historical release equivalence or runtime behavior.
func TestStreamModesKeepAuthenticatedOutput(t *testing.T) {
	var want map[string]string
	if err := json.Unmarshal([]byte(readTestdata(t, "batch-store-authenticated-projection.json")), &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != 10 {
		t.Fatal("incomplete BatchStore source projection")
	}
	// The independent storage fixture was authored after that historical release.
	// Its separate receipt freezes current source bytes, not historical behavior.
	var sampleHashes map[string]string
	if err := json.Unmarshal([]byte(readTestdata(t, "sample-store-default-projection.json")), &sampleHashes); err != nil {
		t.Fatal(err)
	}
	if len(sampleHashes) != 5 {
		t.Fatal("incomplete storage source projection")
	}
	for part, suffix := range map[string]string{"transport": "Transport", "skeleton": "Skeleton", "endpoint": "StreamEndpoint", "runtime": "BoundedStreamRuntime", "adapter": "StreamAPDUAdapter"} {
		want["sample/"+part] = sampleHashes["SampleStore"+suffix+".java"]
	}
	got := map[string]string{}
	record := func(prefix string, r *JavaGenerationResult) {
		for name, source := range map[string][]byte{"transport": r.TransportSource, "skeleton": r.SkeletonSource,
			"endpoint": r.StreamEndpointSource, "runtime": r.StreamRuntimeSource, "adapter": r.StreamAPDUAdapterSource} {
			got[prefix+"/"+name] = fmt.Sprintf("%x", sha256.Sum256(source))
		}
	}
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		record(string(memory), batchStoreResult(t, memory))
	}
	s, err := ParseFile("testdata/sample-store.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.store", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
	if err != nil {
		t.Fatal(err)
	}
	record("sample", r)
	for key, hash := range want {
		if got[key] != hash {
			t.Errorf("%s changed: %s", key, got[key])
		}
	}
	// Positive control: adding one mode changes the runtime, so the freeze is live.
	modes := batchStoreSchema()
	modes.Methods["summarizeBatch"].StreamMode = StreamModeChunked
	r, err = GenerateJavaSkeletonWithOptions(modes, "io.jcrpc.batchstore.server", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(r.StreamRuntimeSource)) == want["clear_on_reset/runtime"] {
		t.Fatal("a mode left the authenticated runtime unchanged")
	}
}

// Source contract of the mode runtime. This is lint, not evidence: every
// clause below is attacked by the behavioral mutants, and the token-preserving
// mutant shows a behavior change that keeps every token.
func streamModesSourceContract(r *JavaGenerationResult) error {
	runtime, skeleton, endpoint := string(r.StreamRuntimeSource), string(r.SkeletonSource), string(r.StreamEndpointSource)
	for _, check := range []struct{ label, source, want string }{
		{"compact endpoint", endpoint, "            byte operation,\n            byte p1,\n"},
		{"mode table", skeleton, "    private static final byte[] STREAM_MODES = {\n        (byte) 1, (byte) 2, (byte) 0, (byte) 2,\n        (byte) 1 };\n"},
		{"installed mode binding", skeleton, "this, this, STREAM_DIRECTIONS, STREAM_LIMITS, STREAM_MODES);"},
		{"gate", runtime, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (scalars[IDX_STATE] == STATE_WRITING &&\n                        scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED))) {\n            rejectWithoutClearing(SW_SECURITY_STATUS_NOT_SATISFIED);"},
		{"chunk record transfer", runtime, "            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(request, requestOffset, requestLength);"},
		{"staging", runtime, "copy(request, requestOffset, workspace, scalars[IDX_INPUT_LENGTH], requestLength);"},
		{"chunked duplicate", runtime, "                // Nothing was staged, so a repeated chunk cannot be proven\n                // identical to the one the handler already consumed.\n                fail(SW_INVALID_DATA);"},
		{"read record transfer", runtime, "        requireNonPersistentOutput(response, callerWorkspace);\n        ((Handler) handlerSlot[IDX_HANDLER]).produceResult("},
		{"descriptor record transfer", runtime, "                    requireRamSpan(responseBuffer);"},
		{"staged digest reset", runtime, "        sha256.resetDigest();\n        sha256.digest(workspace, (short) 0, scalars[IDX_INPUT_LENGTH], digestScratch, (short) 0);"},
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
	if n := strings.Count(runtime, "rejectWithoutClearing("); n != 2 {
		return fmt.Errorf("rejectWithoutClearing appears %d times, want the gate and its definition", n)
	}
	if n := strings.Count(runtime, "copy(response, responseOffset, workspace"); n != 1 {
		return fmt.Errorf("result copies into the workspace: %d, want only the short receipt", n)
	}
	return nil
}

func TestStreamModesSourceContract(t *testing.T) {
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		if err := streamModesSourceContract(modeStoreResult(t, memory)); err != nil {
			t.Fatalf("%s: %v", memory, err)
		}
	}
}

// Generation exposes the public-only cleanup on mixed-mode runtimes, preserving the
// authenticated-only generated contract. Runtime behavior is tested by ModeStoreHarness.
func TestStreamModesPublicInvalidationSurface(t *testing.T) {
	r := modeStoreResult(t, StreamMemoryClearOnDeselect)
	for name, source := range map[string][]byte{"endpoint": r.StreamEndpointSource, "runtime": r.StreamRuntimeSource, "skeleton": r.SkeletonSource} {
		if !strings.Contains(string(source), "abortPublic") {
			t.Errorf("%s lacks public-session invalidation", name)
		}
	}
}

// Known violations must fail the real simulator witness by its intended assertion:
// a no-op retains public authority, and unconditional clearing cancels issuer work.
func TestStreamModesPublicInvalidationControls(t *testing.T) {
	jar := simulatorJar(t)
	const signature = "    public void abortPublic(byte reason) {\n"
	const preserve = "        if (scalars[IDX_STATE] != STATE_EMPTY && scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED) {\n            return;\n        }\n"
	for _, tc := range []struct{ name, anchor, replacement, want string }{
		{"noop", signature, signature + "        if (reason != 0) return;\n", "public invalidation retained upload"},
		{"cancels-authenticated", preserve, "", "public invalidation cancelled issuer upload"},
		{"retains-public-short-receipt", signature, signature + "        if (scalars[IDX_STATE] == STATE_SHORT_CLOSED && scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE) return;\n", "public invalidation retained short receipt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := mutateModeStoreRuntime(t, jar, [][2]string{{tc.anchor, tc.replacement}})
			if err == nil || !strings.Contains(output, tc.want) {
				t.Fatalf("expected %q violation, got %v\n%s", tc.want, err, output)
			}
		})
	}
}

// mutateModeStoreRuntime applies edits whose anchors must each appear exactly once,
// then runs the full behavioral suite.
func mutateModeStoreRuntime(t *testing.T, jar string, edits [][2]string) (string, error) {
	t.Helper()
	r := modeStoreResult(t, StreamMemoryClearOnDeselect)
	source := string(r.StreamRuntimeSource)
	for _, edit := range edits {
		if strings.Count(source, edit[0]) != 1 {
			t.Fatalf("mutation anchor count %d: %q", strings.Count(source, edit[0]), edit[0])
		}
		source = strings.Replace(source, edit[0], edit[1], 1)
	}
	r.StreamRuntimeSource = []byte(source)
	return runModeStore(t, jar, r)
}

// Instrument controls: a same-value 1 B persistent store planted on a refusal
// path, on the accepted chunked path and on an accepted producer read must each
// fail the zero gate by name; the same plant on a transient array stays green.
// A setup failure or another assertion does not count as a kill.
func TestStreamModesLedgerControls(t *testing.T) {
	jar := simulatorJar(t)
	for _, tc := range []struct {
		name, anchor, plant, killed string
	}{
		{"refusal-one-byte", "    private void fail(short statusWord) {\n", "        workspace[0] = workspace[0];\n", "chunked close retry wrote persistent"},
		{"refusal-aliased-one-byte", "    private void fail(short statusWord) {\n", "        byte[] alias = workspace;\n        alias[0] = alias[0];\n", "chunked close retry wrote persistent"},
		{"chunked-success-one-byte", "            sha256.updateDigest(request, requestOffset, requestLength);\n", "            workspace[0] = workspace[0];\n", "chunked first chunk wrote persistent"},
		{"producer-read-one-byte", "        // Produce the chunk again into the admitted RAM span; it is never stored.\n", "        workspace[0] = workspace[0];\n", "public read wrote persistent"},
		{"transient-one-byte", "    private void fail(short statusWord) {\n", "        digestScratch[0] = digestScratch[0];\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := mutateModeStoreRuntime(t, jar, [][2]string{{tc.anchor, tc.anchor + tc.plant}})
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
// guard must reject: one method, one operation, one span, one length or one
// result size. Only the named behavioral assertion counts as a kill.
func TestStreamModesNarrowingMutants(t *testing.T) {
	jar := simulatorJar(t)
	const gate = "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (scalars[IDX_STATE] == STATE_WRITING &&\n"
	const liveUpload = "                (scalars[IDX_STATE] == STATE_WRITING &&\n                        scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED))) {"
	const bound = "        if ((scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF)) {"
	const closeRecordTransfer = "        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);"
	const readRecordTransfer = "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);"
	// workspaceSkipped keeps the response-span half of an output record transfer and
	// drops only its caller-workspace half when cond holds.
	workspaceSkipped := func(anchor, cond string) string {
		head := strings.TrimSuffix(anchor, "        requireNonPersistentOutput(response, callerWorkspace);")
		return head + "        if (" + cond + ") {\n            requireRamSpan(response);\n        } else {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"
	}
	liveUploadFor := func(cond string) string {
		return "                (" + cond + " && scalars[IDX_STATE] == STATE_WRITING &&\n                        scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED))) {"
	}
	boundUnless := func(cond string) string {
		return "        if (" + cond + " && (scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF)) {"
	}
	// Keeps-handle mutants keep the refusal status and its 0 B but leave the
	// stream live when cond holds; only a fitting chunk at the same index
	// tells them apart from the candidate (a CLOSE refuses either way).
	const boundRefusal = bound + "\n            fail(SW_WRONG_LENGTH);"
	const shapeRefusal = "                length > chunkSize || (index < count - 1 && length != chunkSize)) {\n            fail(SW_WRONG_LENGTH);"
	const handlerFailure = "        } catch (StreamStatusWordException e) {\n            if (e != failure) {\n                clearAll();"
	keepsHandle := func(anchor, cond string) string {
		head := strings.TrimSuffix(anchor, "fail(SW_WRONG_LENGTH);")
		return head + "if (" + cond + ") {\n                rejectWithoutClearing(SW_WRONG_LENGTH);\n            }\n            fail(SW_WRONG_LENGTH);"
	}
	for _, tc := range []struct {
		name      string
		edits     [][2]string
		assertion string
	}{
		// Authority.
		{"gate-admits-upload-first-chunk", [][2]string{{gate, "        if (!authenticated && !(methodMode == MODE_AUTHENTICATED && operation == OP_WRITE_OR_INVOKE && p1 == 0 && scalars[IDX_STATE] == STATE_EMPTY) && (methodMode == MODE_AUTHENTICATED ||\n                (scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "pre-auth put staged"},
		{"gate-unprotects-upload-on-abort", [][2]string{{gate, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (operation != OP_ABORT && scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "unauthenticated abort cancelled authenticated upload"},
		{"gate-unprotects-upload-from-chunked", [][2]string{{gate, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (methodMode != MODE_CHUNKED && scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "unauthenticated chunked write cancelled authenticated upload"},
		{"gate-protects-only-write-abort", [][2]string{{liveUpload, liveUploadFor("(operation == OP_WRITE_OR_INVOKE || operation == OP_ABORT)")}}, "unauthenticated foreign close cancelled authenticated upload"},
		{"gate-skips-close-write", [][2]string{{liveUpload, liveUploadFor("operation != OP_CLOSE_WRITE")}}, "unauthenticated foreign close cancelled authenticated upload"},
		{"gate-skips-pending-info", [][2]string{{liveUpload, liveUploadFor("operation != OP_GET_PENDING_READ_INFO")}}, "unauthenticated foreign info cancelled authenticated upload"},
		{"gate-skips-read-chunk", [][2]string{{liveUpload, liveUploadFor("operation != OP_READ_CHUNK")}}, "unauthenticated foreign read cancelled authenticated upload"},
		{"gate-skips-close-read", [][2]string{{liveUpload, liveUploadFor("operation != OP_CLOSE_READ")}}, "unauthenticated foreign close read cancelled authenticated upload"},
		// Request total bound.
		{"bound-skipped-for-public", [][2]string{{bound, boundUnless("scalars[IDX_METHOD_MODE] != MODE_PUBLIC_INVALIDATE")}}, "public request over maximum wrote persistent"},
		{"bound-skipped-for-chunked", [][2]string{{bound, boundUnless("scalars[IDX_METHOD_MODE] != MODE_CHUNKED")}}, "chunked request over maximum wrote persistent"},
		{"bound-skipped-for-record transfer", [][2]string{{bound, boundUnless("scalars[IDX_ACTIVE_METHOD] != 4")}}, "record transfer request over maximum wrote persistent"},
		{"bound-admits-max-plus-one", [][2]string{{bound, "        if ((scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF) + 1) {"}}, "public request over maximum wrote persistent"},
		{"bound-plus-128", [][2]string{{bound, "        if ((scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF) + 128) {"}}, "public request over maximum wrote persistent"},
		// Request total bound and chunk shape: refused, 0 B, but the stream stays live.
		{"bound-refusal-keeps-handle", [][2]string{{boundRefusal, strings.Replace(boundRefusal, "fail(", "rejectWithoutClearing(", 1)}}, "public request over maximum left a live stream"},
		{"bound-refusal-keeps-public-handle", [][2]string{{boundRefusal, keepsHandle(boundRefusal, "scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "public request over maximum left a live stream"},
		{"bound-refusal-keeps-chunked-handle", [][2]string{{boundRefusal, keepsHandle(boundRefusal, "scalars[IDX_METHOD_MODE] == MODE_CHUNKED && scalars[IDX_ACTIVE_METHOD] != 4")}}, "chunked request over maximum left a live stream"},
		{"bound-refusal-keeps-record transfer-handle", [][2]string{{boundRefusal, keepsHandle(boundRefusal, "scalars[IDX_ACTIVE_METHOD] == 4")}}, "record transfer request over maximum left a live stream"},
		{"shape-refusal-keeps-handle", [][2]string{{shapeRefusal, keepsHandle(shapeRefusal, "scalars[IDX_STATE] == STATE_WRITING")}}, "chunked short middle refusal left a live stream"},
		{"shape-refusal-keeps-public-handle", [][2]string{{shapeRefusal, keepsHandle(shapeRefusal, "scalars[IDX_STATE] == STATE_WRITING && scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "public short middle refusal left a live stream"},
		{"shape-refusal-keeps-record transfer-handle", [][2]string{{shapeRefusal, keepsHandle(shapeRefusal, "scalars[IDX_STATE] == STATE_WRITING && scalars[IDX_ACTIVE_METHOD] == 4")}}, "record transfer shape refusal left a live stream"},
		{"handler-chunk-failure-keeps-handle", [][2]string{{handlerFailure, "        } catch (StreamStatusWordException e) {\n            if (e != failure && !(operation == OP_WRITE_OR_INVOKE &&\n                    scalars[IDX_METHOD_MODE] == MODE_CHUNKED && scalars[IDX_NEXT_PACKET_INDEX] != 0)) {\n                clearAll();"}}, "chunked handler chunk failure left a live stream"},
		// Caller-workspace half of output record transfer.
		{"chunked-close-skips-workspace-record transfer", [][2]string{{closeRecordTransfer, workspaceSkipped(closeRecordTransfer, "scalars[IDX_METHOD_MODE] == MODE_CHUNKED")}}, "persistent caller workspace admitted on chunked close"},
		{"record transfer-close-skips-workspace-record transfer", [][2]string{{closeRecordTransfer, workspaceSkipped(closeRecordTransfer, "scalars[IDX_ACTIVE_METHOD] == 4")}}, "persistent caller workspace admitted on record transfer close"},
		{"public-close-skips-workspace-record transfer", [][2]string{{closeRecordTransfer, workspaceSkipped(closeRecordTransfer, "scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "persistent caller workspace admitted on public close"},
		{"record transfer-read-skips-workspace-record transfer", [][2]string{{readRecordTransfer, workspaceSkipped(readRecordTransfer, "scalars[IDX_METHOD_MODE] == MODE_CHUNKED")}}, "persistent caller workspace admitted on record transfer read"},
		{"public-read-skips-workspace-record transfer", [][2]string{{readRecordTransfer, workspaceSkipped(readRecordTransfer, "scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "persistent caller workspace admitted on public read"},
		// Chunked delivery.
		{"chunked-stages-inspection-chunk", [][2]string{{"            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(", "            if (scalars[IDX_ACTIVE_METHOD] == 2) {\n                copy(request, requestOffset, workspace, scalars[IDX_INPUT_LENGTH], requestLength);\n            }\n            requireRamSpan(callerWorkspace);\n            sha256.updateDigest("}}, "chunked first chunk wrote persistent"},
		{"chunked-duplicate-admits-first-packet", [][2]string{{"            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                // Nothing was staged", "            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED && index == 0) {\n                return (short) 0;\n            }\n            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                // Nothing was staged"}}, "chunked changed duplicate wrote persistent"},
		{"chunked-admits-persistent-workspace-for-inspection", [][2]string{{"            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(", "            if (scalars[IDX_ACTIVE_METHOD] != 2) {\n                requireRamSpan(callerWorkspace);\n            }\n            sha256.updateDigest("}}, "persistent caller workspace admitted on chunk"},
		{"chunked-close-skips-digest-for-194-bytes", [][2]string{{"        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {", "        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (scalars[IDX_INPUT_LENGTH] != 194 && !equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {"}}, "chunked bad close digest wrote persistent"},
		{"chunked-close-after-one-packet", [][2]string{{"                (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) != (scalars[IDX_PACKET_COUNT] & 0xFF)) {\n            fail(SW_WRONG_STATE);", "                (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) != (scalars[IDX_PACKET_COUNT] & 0xFF) &&\n                !(scalars[IDX_METHOD_MODE] == MODE_CHUNKED && (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) == 1)) {\n            fail(SW_WRONG_STATE);"}}, "chunked early close wrote persistent"},
		{"chunked-close-admits-persistent-response", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_METHOD_MODE] != MODE_CHUNKED) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on chunked close"},
		{"chunked-close-stores-receipt", [][2]string{{"            fail(SW_WRONG_LENGTH);\n        }\n        clearAll();\n        return produced;", "            fail(SW_WRONG_LENGTH);\n        }\n        if (scalars[IDX_ACTIVE_METHOD] == 2) {\n            copy(response, responseOffset, workspace, (short) 0, produced);\n        }\n        clearAll();\n        return produced;"}}, "chunked close wrote persistent"},
		{"chunked-begin-inherits-digest", [][2]string{{"            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                sha256.resetDigest();", "            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED && p2 != 2) {\n                sha256.resetDigest();"}}, "chunked fresh session after reset close wrote persistent"},
		// Public producer.
		{"read-admits-persistent-first-chunk", [][2]string{{"        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);", "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        if (index != 0) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent read span admitted"},
		{"close-caches-first-preview-chunk", [][2]string{{"            sha256.updateDigest(response, responseOffset, length);\n", "            sha256.updateDigest(response, responseOffset, length);\n            if (offset == 0 && method == 1) {\n                copy(response, responseOffset, workspace, (short) 0, length);\n            }\n"}}, "public close wrote persistent"},
		{"close-caches-storage-window-prefix", [][2]string{{"            sha256.updateDigest(response, responseOffset, length);\n", "            sha256.updateDigest(response, responseOffset, length);\n            if (offset == 0 && method == 4) {\n                copy(response, responseOffset, workspace, (short) 0, (short) 32);\n            }\n"}}, "record transfer close wrote persistent"},
		{"record transfer-close-skips-digest-for-352-bytes", [][2]string{{"        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {", "        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (scalars[IDX_INPUT_LENGTH] != 352 && !equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {"}}, "record transfer bad close digest wrote persistent"},
		{"read-admits-persistent-for-record transfer", [][2]string{{"        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);", "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        if (scalars[IDX_ACTIVE_METHOD] != 4) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent read span admitted on record transfer"},
		{"result-admits-empty", [][2]string{{"        if (total <= 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {", "        if (total < 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {"}}, "public prepare refusal 7 wrote persistent"},
		{"result-admits-max-plus-one", [][2]string{{"        if (total <= 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {", "        if (total <= 0 || total > (short) (scalars[IDX_RESPONSE_MAX_LENGTH] + 1)) {"}}, "public prepare refusal 6 wrote persistent"},
		{"descriptor-admits-persistent-for-two-packets", [][2]string{{"                    requireRamSpan(responseBuffer);", "                    if (scalars[IDX_RESULT_PACKET_COUNT] != 2) {\n                        requireRamSpan(responseBuffer);\n                    }"}}, "persistent descriptor span admitted"},
		{"close-admits-persistent-for-envelope", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 1) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on public close"},
		{"close-admits-persistent-for-record transfer", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 4) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on record transfer close"},
		{"close-admits-persistent-for-upload", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 3) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on upload close"},
		{"upload-foreign-write-keeps-handle", [][2]string{{"                    // A refused authenticated APDU invalidates the live handle.\n                    fail(SW_WRONG_STATE);", "                    // A refused authenticated APDU invalidates the live handle.\n                    if (scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED) {\n                        rejectWithoutClearing(SW_WRONG_STATE);\n                    }\n                    fail(SW_WRONG_STATE);"}}, "upload foreign refusal retained live handle"},
		{"bad-read-index-keeps-handle", [][2]string{{"        if (count != (scalars[IDX_RESULT_PACKET_COUNT] & 0xFF) || index >= count) {\n            fail(SW_INVALID_DATA);", "        if (count != (scalars[IDX_RESULT_PACKET_COUNT] & 0xFF) || index >= count) {\n            if (index == count) {\n                rejectWithoutClearing(SW_INVALID_DATA);\n            }\n            fail(SW_INVALID_DATA);"}}, "public bad read index retained live handle"},
		{"public-foreign-write-keeps-handle", [][2]string{{"                    // A refused authenticated APDU invalidates the live handle.\n                    fail(SW_WRONG_STATE);", "                    // A refused authenticated APDU invalidates the live handle.\n                    if (scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE) {\n                        rejectWithoutClearing(SW_WRONG_STATE);\n                    }\n                    fail(SW_WRONG_STATE);"}}, "public foreign write retained live handle"},
		{"public-foreign-close-keeps-handle", [][2]string{{"                    scalars[IDX_ACTIVE_METHOD] != methodId) {\n                fail(SW_WRONG_STATE);", "                    scalars[IDX_ACTIVE_METHOD] != methodId) {\n                if (scalars[IDX_STATE] != STATE_EMPTY && scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE) {\n                    rejectWithoutClearing(SW_WRONG_STATE);\n                }\n                fail(SW_WRONG_STATE);"}}, "public foreign refusal retained live handle"},
		{"public-changed-duplicate-admits-one-byte", [][2]string{{"                    !equalsRange(workspace, scalars[IDX_LAST_CHUNK_OFFSET],\n                            request, requestOffset, requestLength)) {", "                    (!equalsRange(workspace, scalars[IDX_LAST_CHUNK_OFFSET],\n                            request, requestOffset, requestLength) && request[(short) (requestOffset + 7)] == workspace[(short) (scalars[IDX_LAST_CHUNK_OFFSET] + 7)])) {"}}, "public changed duplicate wrote persistent"},
		{"staged-close-inherits-digest-for-envelope", [][2]string{{"        // The engine is shared with running digests; never inherit their state.\n        sha256.resetDigest();", "        // The engine is shared with running digests; never inherit their state.\n        if (scalars[IDX_ACTIVE_METHOD] != 1) {\n            sha256.resetDigest();\n        }"}}, "public close after digest pass failure"},
		// Runtime begin.
		{"begin-admits-authenticated-streamed-result-of-64", [][2]string{{"                (responseEnabled && methodMode == MODE_AUTHENTICATED) ||", "                (responseEnabled && methodMode == MODE_AUTHENTICATED && responseLimit != 64) ||"}}, "authenticated streamed result admitted"},
		{"begin-admits-chunked-without-request", [][2]string{{"                !requestEnabled ||\n                (responseEnabled && methodMode == MODE_AUTHENTICATED) ||", "                (!requestEnabled && methodMode != MODE_CHUNKED) ||\n                (responseEnabled && methodMode == MODE_AUTHENTICATED) ||"}}, "chunked method without request stream admitted"},
		{"begin-admits-mode-three", [][2]string{{"                (methodMode != MODE_AUTHENTICATED && methodMode != MODE_PUBLIC_INVALIDATE &&\n                        methodMode != MODE_CHUNKED)) {", "                (methodMode != MODE_AUTHENTICATED && methodMode != MODE_PUBLIC_INVALIDATE &&\n                        methodMode != MODE_CHUNKED && methodMode != 3)) {"}}, "unknown stream mode admitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := mutateModeStoreRuntime(t, jar, tc.edits)
			if err == nil || !strings.Contains(output, "AssertionError: "+tc.assertion) {
				t.Fatalf("survivor (no named failure): %v\n%s", err, output)
			}
			t.Logf("killed %s by TestStreamModesRealSimulator: %s", tc.name, tc.assertion)
		})
	}
}

// The source contract is lint: a mutant that keeps every token it searches for
// but stages each chunked chunk byte by byte passes the text check and must be
// killed by the behavioral suite.
func TestStreamModesTokenPreservingMutant(t *testing.T) {
	jar := simulatorJar(t)
	r := modeStoreResult(t, StreamMemoryClearOnDeselect)
	anchor := "            sha256.updateDigest(request, requestOffset, requestLength);\n"
	source := string(r.StreamRuntimeSource)
	if strings.Count(source, anchor) != 1 {
		t.Fatal("mutation anchor")
	}
	r.StreamRuntimeSource = []byte(strings.Replace(source, anchor, anchor+
		"            for (short i = 0; i < requestLength; i++) {\n                workspace[(short) (scalars[IDX_INPUT_LENGTH] + i)] = request[(short) (requestOffset + i)];\n            }\n", 1))
	if err := streamModesSourceContract(r); err != nil {
		t.Fatalf("mutant does not preserve the searched tokens: %v", err)
	}
	output, err := runModeStore(t, jar, r)
	if err == nil || !strings.Contains(output, "AssertionError: chunked first chunk wrote persistent") {
		t.Fatalf("token-preserving survivor: %v\n%s", err, output)
	}
	t.Log("killed token-preserving chunked byte staging by TestStreamModesRealSimulator: chunked first chunk wrote persistent")
}

// Generation-time narrowing mutants: each validation stays present and admits
// exactly one INS in the class it must refuse. The named Go test must fail on
// the mutated module copy; a build failure is not a kill.
func TestStreamModeGenerationNarrowingMutants(t *testing.T) {
	if testing.Short() {
		t.Skip("copies the module and runs go test")
	}
	for _, tc := range []struct{ name, file, from, to, killed string }{
		{"mode-admits-response-only-for-0x23", "codegen/internal/render/stream_modes.go",
			"if method.RequestStream == nil {",
			"if method.RequestStream == nil && method.INS != 0x23 {",
			"TestStreamModeValidation/chunked-response-only"},
		{"authenticated-admits-streamed-result-for-0x43", "codegen/internal/render/stream_authenticated.go",
			"if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" {",
			"if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" && method.INS != 0x43 {",
			"TestStreamModeValidation/authenticated-streamed-result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			target := filepath.Join(root, tc.file)
			source, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(source), tc.from) != 1 {
				t.Fatal("mutation anchor")
			}
			writeTestFile(t, target, []byte(strings.Replace(string(source), tc.from, tc.to, 1)))
			cmd := exec.Command("go", "test", "./codegen", "-run", "^TestStreamModeValidation$", "-count=1", "-v")
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "--- FAIL: "+tc.killed) {
				t.Fatalf("survivor: %v\n%s", err, output)
			}
			t.Logf("killed %s by %s", tc.name, tc.killed)
		})
	}
}

// SampleStore's two upload-only streams are compared with all four streams.
// The independently declared limits predict 512 B more workspace, two more
// stream rows and one mode byte per stream, plus a 2 B transient mode scalar.
// Provider/JCRE arrays and object headers are outside this generated payload.
func TestStreamModesAllocationPayload(t *testing.T) {
	jar := simulatorJar(t)
	measure := func(s *Schema) (transient, persistent, workspace int, output string) {
		r, err := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.store", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
		if err != nil {
			t.Fatal(err)
		}
		signatures := regexp.MustCompile(`protected abstract ([\s\S]*?);`).FindAllStringSubmatch(string(r.SkeletonSource), -1)
		var methods strings.Builder
		for _, signature := range signatures {
			body := "return (short)0;"
			switch {
			case strings.HasPrefix(signature[1], "byte on"):
				body = "return (byte)0;"
			case strings.HasPrefix(signature[1], "void on"):
				body = ""
			}
			fmt.Fprintf(&methods, "protected %s { %s }\n", signature[1], body)
		}
		fixture := strings.Replace(strings.ReplaceAll(allocationApplet, "METHODS", methods.String()),
			"adapter.processIfStream(apdu);", "adapter.processIfStream(apdu, false);", 1)
		output = runRealJava(t, jar, r, fixture, allocationHarness, "AllocationHarness")
		for _, line := range regexp.MustCompile(`(?m)^skeleton\.(\S+): (transient|persistent) \S+ payload=(\d+) B`).FindAllStringSubmatch(output, -1) {
			var n int
			fmt.Sscan(line[3], &n)
			if line[2] == "transient" {
				transient += n
			} else {
				persistent += n
			}
			if strings.HasSuffix(line[1], ".workspace") {
				workspace = n
			}
		}
		if !strings.Contains(output, "adapter.ioScratch: transient byte[255] payload=255 B") {
			t.Fatalf("adapter I/O array not observed\n%s", output)
		}
		return transient, persistent, workspace, output
	}
	requestOnly := sampleWithModes(t)
	delete(requestOnly.Methods, "exchangePages")
	delete(requestOnly.Methods, "enumeratePages")
	streamed := 0
	for name, method := range requestOnly.Methods {
		method.StreamMode = ""
		if method.HasStream() {
			streamed++
		}
		_ = name
	}
	baseT, baseP, baseW, baseOut := measure(requestOnly)
	modesT, modesP, modesW, modesOut := measure(sampleWithModes(t))
	streamed += 2
	// Independent input limits: two upload methods need 1024 B; adding page
	// exchange requires 1536 B. The two extra INS bytes occur once. Directions
	// (one byte/row), limits (five shorts/row) and mixed modes (one byte/method)
	// exist in both generated tables and immutable runtime-owned copies.
	wantP := baseP + 512 + 2 + 2*(2+2*5*2+streamed)
	t.Logf("authenticated-invalidate upload-only storage: transient=%d B persistent=%d B workspace=%d B\n%s", baseT, baseP, baseW, baseOut)
	t.Logf("per-method modes full storage: transient=%d B persistent=%d B workspace=%d B (%d streamed methods)\n%s", modesT, modesP, modesW, streamed, modesOut)
	if modesT != baseT+2 || modesP != wantP || modesW != 1536 || baseW != 1024 {
		t.Fatalf("payload delta: base %d/%d/%d, modes %d/%d/%d, predicted persistent %d", baseT, baseP, baseW, modesT, modesP, modesW, wantP)
	}
}

// The converter, not javac, decides Java Card Classic compatibility: the mode
// runtime and a fixture using every mode callback (page hashing included)
// convert and verify with the pinned 3.0.5u4 kit for both lifecycle choices.
// Conversion proves no target RAM, NVM or physical-card behavior.
func TestStreamModesClassicCAP(t *testing.T) {
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
			r := modeStoreResult(t, memory)
			root := t.TempDir()
			sourceDir := filepath.Join(root, "src", "io", "jcrpc", "modestore", "server")
			for name, source := range map[string][]byte{
				r.TransportName + ".java": r.TransportSource, r.SkeletonName + ".java": r.SkeletonSource,
				r.StreamEndpointName + ".java": r.StreamEndpointSource, r.StreamRuntimeName + ".java": r.StreamRuntimeSource,
				r.StreamAPDUAdapterName + ".java": r.StreamAPDUAdapterSource, "ModeStoreCAPApplet.java": []byte(readTestdata(t, "ModeStoreCAPApplet.java")),
			} {
				writeTestFile(t, filepath.Join(sourceDir, name), source)
			}
			buildXML := fmt.Sprintf(`<project name="stream-modes-cap" default="cap">
    <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/>
    <target name="cap">
        <javacard>
            <cap jckit="%s" sources="%s" package="io.jcrpc.modestore.server" aid="F000000104" version="1.0" ints="true" output="%s">
                <applet class="io.jcrpc.modestore.server.ModeStoreCAPApplet" aid="F00000010401"/>
            </cap>
        </javacard>
    </target>
</project>
`, filepath.ToSlash(jar), filepath.ToSlash(kit), filepath.ToSlash(filepath.Join(root, "src")), filepath.ToSlash(filepath.Join(root, "modestore.cap")))
			writeTestFile(t, filepath.Join(root, "build.xml"), []byte(buildXML))
			command := exec.Command(ant, "-f", filepath.Join(root, "build.xml"), "cap")
			command.Dir = root
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("CAP conversion failed: %v\n%s", err, output)
			}
			info, err := os.Stat(filepath.Join(root, "modestore.cap"))
			if err != nil || info.Size() == 0 {
				t.Fatalf("CAP output missing: %v", err)
			}
			t.Logf("verified CAP ZIP=%d B\n%s", info.Size(), output)
		})
	}
}
