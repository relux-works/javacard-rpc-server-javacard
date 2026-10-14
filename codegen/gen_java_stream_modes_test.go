package codegen

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

// rev4ShapeSchema mirrors the Auth applet's three stream classes in one
// applet: a public option-A provisioning call with a streamed result (INS
// 0x10), zero-NVM chunked signatures with an exact 73 B result (INS 0x20) and
// with a signature + Cert_adm streamed result (INS 0x70, 320 B transcript,
// 1408 B result), and an authenticated issuer upload (INS 0x58, exact 36 B
// result). It is a fixture, not the Auth contract.
func rev4ShapeSchema() *Schema {
	stream := func(max int) *Message {
		return &Message{Fields: []Field{{Name: "packet", Type: FieldTypeStream, MaxLength: max, ChunkSize: 192}}}
	}
	return &Schema{
		Applet: Applet{Name: "Rev4Shape", Version: "1.0.0", AID: "F00000010401", CLA: 0xB0,
			StreamWorkspace: "persistent", StreamWorkspaceCleanup: StreamWorkspaceCleanupAuthenticatedInvalidate},
		Methods: map[string]*Method{
			"getVersion": {Name: "getVersion", INS: 0x01, Response: &Message{Fields: []Field{{Name: "version", Type: FieldTypeU8}}}},
			"buildEnvelope": {Name: "buildEnvelope", INS: 0x10, StreamMode: StreamModePublicInvalidate,
				Request: stream(1792), Response: stream(1792)},
			"signTranscript": {Name: "signTranscript", INS: 0x20, StreamMode: StreamModeChunked, Request: stream(2048), Response: &Message{Fields: []Field{
				{Name: "signatureLength", Type: FieldTypeU8}, {Name: "signature", Type: FieldTypeBytesFixed, FixedLength: 72}}}},
			"putLeaf": {Name: "putLeaf", INS: 0x58, Request: stream(2048), Response: &Message{Fields: []Field{
				{Name: "generation", Type: FieldTypeU32}, {Name: "digest", Type: FieldTypeBytesFixed, FixedLength: 32}}}},
			"signAdmission": {Name: "signAdmission", INS: 0x70, StreamMode: StreamModeChunked,
				Request: stream(320), Response: stream(1408)},
		},
	}
}

func rev4ShapeResult(t *testing.T, memory StreamMemory) *JavaGenerationResult {
	t.Helper()
	r, err := GenerateJavaSkeletonWithOptions(rev4ShapeSchema(), "io.jcrpc.rev4shape.server", JavaOptions{StreamMemory: memory})
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

func runRev4Shape(t *testing.T, jar string, r *JavaGenerationResult) (string, error) {
	t.Helper()
	return runRealJavaResult(t, jar, instrumentNvm(t, r), readTestdata(t, "Rev4ShapeApplet.java"),
		readTestdata(t, "Rev4ShapeHarness.java"), "Rev4ShapeHarness")
}

// Real Simulator.transmitCommand -> Rev4ShapeApplet.process -> (generated
// adapter processIfStream | Auth-shaped direct dispatchStreamTo over one APDU
// buffer) -> runtime.dispatch, on both lifecycle choices. Every APDU asserts
// its status word and its logical persistent store count: chunked APDUs make
// 0 B on success and refusal, public APDUs make exactly the accepted chunk
// length or 0 B, and each refusal is followed by a dead-stream check and a
// nearby accepted control. Logical stores include same-value stores; JCRE
// journaling, Signature/MessageDigest internal state and physical EEPROM are
// outside this ledger.
func TestStreamModesRealSimulator(t *testing.T) {
	jar := simulatorJar(t)
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		t.Run(string(memory), func(t *testing.T) {
			output, err := runRev4Shape(t, jar, rev4ShapeResult(t, memory))
			if err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
			t.Log(output)
		})
	}
}

// authWithModes is the real Auth fixture with the owner-selected REV4 modes:
// public-invalidate provisioning (INS 0x10 only), chunked signatures and
// admission (INS 0x20/0x30/0x40/0x70), and the issuer methods left on the
// authenticated contract.
func authWithModes(t *testing.T) *Schema {
	t.Helper()
	s, err := ParseFile("testdata/bsim-auth.json")
	if err != nil {
		t.Fatal(err)
	}
	s.Applet.StreamWorkspace = "persistent"
	s.Applet.StreamWorkspaceCleanup = StreamWorkspaceCleanupAuthenticatedInvalidate
	for name, mode := range map[string]string{
		"buildProvisioningEnvelopeV3":   StreamModePublicInvalidate,
		"signAdmissionV1":               StreamModeChunked,
		"signAuthenticationChallengeV1": StreamModeChunked,
		"signAuthenticationSessionV1":   StreamModeChunked,
		"signMigrationIntentV1":         StreamModeChunked,
	} {
		if s.Methods[name] == nil {
			t.Fatalf("Auth fixture lacks %s", name)
		}
		s.Methods[name].StreamMode = mode
	}
	return s
}

// Generation refuses every misplaced or unknown mode by name and returns no
// partial package; the Rev4 fixture and the real Auth fixture with its modes
// are the positive controls, so a validator that refuses everything fails.
func TestStreamModeValidation(t *testing.T) {
	options := pluginapi.Options{Namespace: "io.jcrpc.rev4shape.server", SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"}
	for _, tc := range []struct {
		name   string
		mutate func(*Schema)
		want   string
	}{
		{"unknown-mode", func(s *Schema) { s.Methods["signTranscript"].StreamMode = "Chunked" }, `signTranscript (INS 0x20): unknown stream mode "Chunked"`},
		{"padded-mode", func(s *Schema) { s.Methods["signTranscript"].StreamMode = "chunked " }, `unknown stream mode "chunked "`},
		{"ordinary-method", func(s *Schema) { s.Methods["getVersion"].StreamMode = StreamModeChunked }, `getVersion (INS 0x01): stream mode "chunked" applies only to a streamed method`},
		{"whole-reply-area", func(s *Schema) { s.Applet.StreamWorkspaceCleanup = pluginapi.StreamWorkspaceCleanupWholeReplyArea }, `requires stream_workspace_cleanup "authenticated-invalidate"`},
		{"released-default", func(s *Schema) { s.Applet.StreamWorkspaceCleanup = "" }, `requires stream_workspace_cleanup "authenticated-invalidate"`},
		{"chunked-response-only", func(s *Schema) {
			s.Methods["signTranscript"].Request = nil
			s.Methods["signTranscript"].Response = s.Methods["signAdmission"].Response
		}, `signTranscript (INS 0x20): stream mode "chunked" requires a request stream`},
		{"response-only-public", func(s *Schema) {
			s.Methods["signTranscript"].Request = nil
			s.Methods["signTranscript"].Response = s.Methods["signAdmission"].Response
			s.Methods["signTranscript"].StreamMode = StreamModePublicInvalidate
		}, `signTranscript (INS 0x20): stream mode "public-invalidate" requires a request stream`},
		{"authenticated-streamed-result", func(s *Schema) { s.Methods["signAdmission"].StreamMode = "" }, `signAdmission (INS 0x70)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rev4ShapeSchema()
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
	if files, err := (Plugin{}).Generate(rev4ShapeSchema(), options); err != nil || len(files) != 7 {
		t.Fatalf("Rev4 fixture refused: %d %v", len(files), err)
	}
	auth := pluginapi.Options{Namespace: "ru.mts.bsimid.applet.auth", StreamMemory: "clear_on_reset", SimulatorDependency: "works.relux:jcardsim:3.0.5.9-relux.3"}
	files, err := (Plugin{}).Generate(authWithModes(t), auth)
	if err != nil || len(files) != 7 {
		t.Fatalf("Auth fixture with modes refused: %v", err)
	}
	// Without a mode on its streamed-result method the Auth fixture is refused again.
	s := authWithModes(t)
	s.Methods["signAdmissionV1"].StreamMode = ""
	if _, err := (Plugin{}).Generate(s, auth); err == nil || !strings.Contains(err.Error(), "signAdmissionV1 (INS 0x70)") {
		t.Fatalf("authenticated streamed result admitted: %v", err)
	}
}

// Schemas without any stream mode keep the reviewed L2 output byte for byte:
// the authenticated-invalidate fixture at backend d27f2ca088c7 (both lifecycle
// choices) and the released Auth fixture. This freezes generation, not behavior.
func TestStreamModesKeepAuthenticatedOutput(t *testing.T) {
	want := map[string]string{
		"clear_on_deselect/transport": "593285166bdda919ae72c06dcbc98bd437143884658911a6e4168601430ced4a",
		"clear_on_deselect/skeleton":  "2796affcc0dd61e424132f030ddf14a486c719c3017c688eb062b91c072e6356",
		"clear_on_deselect/endpoint":  "fbe57e0af5893d14aebd6b67b40db805383aabe6a4c5345ced651fa5ad2cfd8e",
		"clear_on_deselect/runtime":   "59cb9c6ff2b0b95f8bddaa9bfe24893f44ddf23ffd9372d732bd3e995862f39b",
		"clear_on_deselect/adapter":   "ab39fbb6e95a12986dd2ef58dd5d5f1573d33b35ef389d595f334b1877b77a93",
		"clear_on_reset/transport":    "593285166bdda919ae72c06dcbc98bd437143884658911a6e4168601430ced4a",
		"clear_on_reset/skeleton":     "75d9de597fdc5e5510a25a01518531f9ff672623b5b40d78c611d9a20c54a84c",
		"clear_on_reset/endpoint":     "fbe57e0af5893d14aebd6b67b40db805383aabe6a4c5345ced651fa5ad2cfd8e",
		"clear_on_reset/runtime":      "3d54930ddd48469d03bdd14b1c943d1ab534c9a8b703800738d78431c52ad194",
		"clear_on_reset/adapter":      "eb2c42d978487c8c46bf7ad22882b87c1c2a17d298c1425d6b834e1fd5e5cb06",
		"released-auth/transport":     "75ff6fd4b035769347be3c6debe4e458e0141a0544f2f779a727939c626fb279",
		"released-auth/skeleton":      "b7504b28eb611d856c1d0dba53f5a30fdd3f8ea4fdaa4e48196c351eb4813f03",
		"released-auth/endpoint":      "ad1c1af8a05c3b9138b00f5a368b9290c7f0935787a19656ddbd8f6a25eb8539",
		"released-auth/runtime":       "cf7ebb85a4d253c0c77559753efe56f3b7178b035ae5c5195d79a3ec24dedf34",
		"released-auth/adapter":       "2cc5793bc033325919522eddfe54d2ecb7db6b4b0bf9fbc6fa88f9216c336c1b",
	}
	got := map[string]string{}
	record := func(prefix string, r *JavaGenerationResult) {
		for name, source := range map[string][]byte{"transport": r.TransportSource, "skeleton": r.SkeletonSource,
			"endpoint": r.StreamEndpointSource, "runtime": r.StreamRuntimeSource, "adapter": r.StreamAPDUAdapterSource} {
			got[prefix+"/"+name] = fmt.Sprintf("%x", sha256.Sum256(source))
		}
	}
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		record(string(memory), authShapeResult(t, memory))
	}
	s, err := ParseFile("testdata/bsim-auth.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := GenerateJavaSkeletonWithOptions(s, "ru.mts.bsimid.applet.auth", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
	if err != nil {
		t.Fatal(err)
	}
	record("released-auth", r)
	for key, hash := range want {
		if got[key] != hash {
			t.Errorf("%s changed: %s", key, got[key])
		}
	}
	// Positive control: adding one mode changes the runtime, so the freeze is live.
	modes := authShapeSchema()
	modes.Methods["signTranscript"].StreamMode = StreamModeChunked
	r, err = GenerateJavaSkeletonWithOptions(modes, "io.jcrpc.authshape.server", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
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
		{"mode parameter", endpoint, "            byte operation,\n            byte methodMode,\n"},
		{"mode table", skeleton, "    private static final byte[] STREAM_MODES = {\n        (byte) 1, (byte) 2, (byte) 0, (byte) 2 };\n"},
		{"mode forwarding", skeleton, "operation, STREAM_MODES[row],"},
		{"gate", runtime, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (scalars[IDX_STATE] == STATE_WRITING &&\n                        scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED))) {\n            rejectWithoutClearing(SW_SECURITY_STATUS_NOT_SATISFIED);"},
		{"chunk admission", runtime, "            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(request, requestOffset, requestLength);"},
		{"staging", runtime, "copy(request, requestOffset, workspace, scalars[IDX_INPUT_LENGTH], requestLength);"},
		{"chunked duplicate", runtime, "                // Nothing was staged, so a repeated chunk cannot be proven\n                // identical to the one the handler already consumed.\n                fail(SW_INVALID_DATA);"},
		{"read admission", runtime, "        requireNonPersistentOutput(response, callerWorkspace);\n        ((Handler) handlerSlot[IDX_HANDLER]).produceResult("},
		{"descriptor admission", runtime, "                    requireRamSpan(responseBuffer);"},
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
		if err := streamModesSourceContract(rev4ShapeResult(t, memory)); err != nil {
			t.Fatalf("%s: %v", memory, err)
		}
	}
}

// mutateRev4Runtime applies edits whose anchors must each appear exactly once,
// then runs the full behavioral suite.
func mutateRev4Runtime(t *testing.T, jar string, edits [][2]string) (string, error) {
	t.Helper()
	r := rev4ShapeResult(t, StreamMemoryClearOnDeselect)
	source := string(r.StreamRuntimeSource)
	for _, edit := range edits {
		if strings.Count(source, edit[0]) != 1 {
			t.Fatalf("mutation anchor count %d: %q", strings.Count(source, edit[0]), edit[0])
		}
		source = strings.Replace(source, edit[0], edit[1], 1)
	}
	r.StreamRuntimeSource = []byte(source)
	return runRev4Shape(t, jar, r)
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
			output, err := mutateRev4Runtime(t, jar, [][2]string{{tc.anchor, tc.anchor + tc.plant}})
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
	const closeAdmission = "        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);"
	const readAdmission = "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);"
	// workspaceSkipped keeps the response-span half of an output admission and
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
	for _, tc := range []struct {
		name      string
		edits     [][2]string
		assertion string
	}{
		// Authority.
		{"gate-admits-issuer-first-chunk", [][2]string{{gate, "        if (!authenticated && !(methodMode == MODE_AUTHENTICATED && operation == OP_WRITE_OR_INVOKE && p1 == 0 && scalars[IDX_STATE] == STATE_EMPTY) && (methodMode == MODE_AUTHENTICATED ||\n                (scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "pre-auth put staged"},
		{"gate-unprotects-issuer-on-abort", [][2]string{{gate, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (operation != OP_ABORT && scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "unauthenticated abort cancelled issuer upload"},
		{"gate-unprotects-issuer-from-chunked", [][2]string{{gate, "        if (!authenticated && (methodMode == MODE_AUTHENTICATED ||\n                (methodMode != MODE_CHUNKED && scalars[IDX_STATE] == STATE_WRITING &&\n"}}, "unauthenticated chunked write cancelled issuer upload"},
		{"gate-protects-only-write-abort", [][2]string{{liveUpload, liveUploadFor("(operation == OP_WRITE_OR_INVOKE || operation == OP_ABORT)")}}, "unauthenticated foreign close cancelled issuer upload"},
		{"gate-skips-close-write", [][2]string{{liveUpload, liveUploadFor("operation != OP_CLOSE_WRITE")}}, "unauthenticated foreign close cancelled issuer upload"},
		{"gate-skips-pending-info", [][2]string{{liveUpload, liveUploadFor("operation != OP_GET_PENDING_READ_INFO")}}, "unauthenticated foreign info cancelled issuer upload"},
		{"gate-skips-read-chunk", [][2]string{{liveUpload, liveUploadFor("operation != OP_READ_CHUNK")}}, "unauthenticated foreign read cancelled issuer upload"},
		{"gate-skips-close-read", [][2]string{{liveUpload, liveUploadFor("operation != OP_CLOSE_READ")}}, "unauthenticated foreign close read cancelled issuer upload"},
		// Request total bound.
		{"bound-skipped-for-public", [][2]string{{bound, boundUnless("scalars[IDX_METHOD_MODE] != MODE_PUBLIC_INVALIDATE")}}, "public request over maximum wrote persistent"},
		{"bound-skipped-for-chunked", [][2]string{{bound, boundUnless("scalars[IDX_METHOD_MODE] != MODE_CHUNKED")}}, "chunked request over maximum wrote persistent"},
		{"bound-skipped-for-admission", [][2]string{{bound, boundUnless("scalars[IDX_ACTIVE_METHOD] != 4")}}, "admission request over maximum wrote persistent"},
		{"bound-admits-max-plus-one", [][2]string{{bound, "        if ((scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF) + 1) {"}}, "public request over maximum wrote persistent"},
		{"bound-plus-128", [][2]string{{bound, "        if ((scalars[IDX_INPUT_LENGTH] & 0xFFFF) + length >\n                (scalars[IDX_REQUEST_MAX_LENGTH] & 0xFFFF) + 128) {"}}, "public request over maximum wrote persistent"},
		// Caller-workspace half of output admission.
		{"chunked-close-skips-workspace-admission", [][2]string{{closeAdmission, workspaceSkipped(closeAdmission, "scalars[IDX_METHOD_MODE] == MODE_CHUNKED")}}, "persistent caller workspace admitted on chunked close"},
		{"admission-close-skips-workspace-admission", [][2]string{{closeAdmission, workspaceSkipped(closeAdmission, "scalars[IDX_ACTIVE_METHOD] == 4")}}, "persistent caller workspace admitted on admission close"},
		{"public-close-skips-workspace-admission", [][2]string{{closeAdmission, workspaceSkipped(closeAdmission, "scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "persistent caller workspace admitted on public close"},
		{"admission-read-skips-workspace-admission", [][2]string{{readAdmission, workspaceSkipped(readAdmission, "scalars[IDX_METHOD_MODE] == MODE_CHUNKED")}}, "persistent caller workspace admitted on admission read"},
		{"public-read-skips-workspace-admission", [][2]string{{readAdmission, workspaceSkipped(readAdmission, "scalars[IDX_METHOD_MODE] == MODE_PUBLIC_INVALIDATE")}}, "persistent caller workspace admitted on public read"},
		// Chunked delivery.
		{"chunked-stages-sign-chunk", [][2]string{{"            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(", "            if (scalars[IDX_ACTIVE_METHOD] == 2) {\n                copy(request, requestOffset, workspace, scalars[IDX_INPUT_LENGTH], requestLength);\n            }\n            requireRamSpan(callerWorkspace);\n            sha256.updateDigest("}}, "chunked first chunk wrote persistent"},
		{"chunked-duplicate-admits-first-packet", [][2]string{{"            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                // Nothing was staged", "            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED && index == 0) {\n                return (short) 0;\n            }\n            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                // Nothing was staged"}}, "chunked changed duplicate wrote persistent"},
		{"chunked-admits-persistent-workspace-for-sign", [][2]string{{"            requireRamSpan(callerWorkspace);\n            sha256.updateDigest(", "            if (scalars[IDX_ACTIVE_METHOD] != 2) {\n                requireRamSpan(callerWorkspace);\n            }\n            sha256.updateDigest("}}, "persistent caller workspace admitted on chunk"},
		{"chunked-close-skips-digest-for-194-bytes", [][2]string{{"        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {", "        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (scalars[IDX_INPUT_LENGTH] != 194 && !equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {"}}, "chunked bad close digest wrote persistent"},
		{"chunked-close-after-one-packet", [][2]string{{"                (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) != (scalars[IDX_PACKET_COUNT] & 0xFF)) {\n            fail(SW_WRONG_STATE);", "                (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) != (scalars[IDX_PACKET_COUNT] & 0xFF) &&\n                !(scalars[IDX_METHOD_MODE] == MODE_CHUNKED && (scalars[IDX_NEXT_PACKET_INDEX] & 0xFF) == 1)) {\n            fail(SW_WRONG_STATE);"}}, "chunked early close wrote persistent"},
		{"chunked-close-admits-persistent-response", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_METHOD_MODE] != MODE_CHUNKED) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on chunked close"},
		{"chunked-close-stores-receipt", [][2]string{{"            fail(SW_WRONG_LENGTH);\n        }\n        clearAll();\n        return produced;", "            fail(SW_WRONG_LENGTH);\n        }\n        if (scalars[IDX_ACTIVE_METHOD] == 2) {\n            copy(response, responseOffset, workspace, (short) 0, produced);\n        }\n        clearAll();\n        return produced;"}}, "chunked close wrote persistent"},
		{"chunked-begin-inherits-digest", [][2]string{{"            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED) {\n                sha256.resetDigest();", "            if (scalars[IDX_METHOD_MODE] == MODE_CHUNKED && p2 != 2) {\n                sha256.resetDigest();"}}, "chunked fresh session after reset close wrote persistent"},
		// Public producer.
		{"read-admits-persistent-first-chunk", [][2]string{{"        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);", "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        if (index != 0) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent read span admitted"},
		{"close-caches-first-envelope-chunk", [][2]string{{"            sha256.updateDigest(response, responseOffset, length);\n", "            sha256.updateDigest(response, responseOffset, length);\n            if (offset == 0 && method == 1) {\n                copy(response, responseOffset, workspace, (short) 0, length);\n            }\n"}}, "public close wrote persistent"},
		{"close-caches-admission-signature", [][2]string{{"            sha256.updateDigest(response, responseOffset, length);\n", "            sha256.updateDigest(response, responseOffset, length);\n            if (offset == 0 && method == 4) {\n                copy(response, responseOffset, workspace, (short) 0, (short) 73);\n            }\n"}}, "admission close wrote persistent"},
		{"admission-close-skips-digest-for-320-bytes", [][2]string{{"        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (!equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {", "        sha256.digest(request, digestOffset, (short) 0, digestScratch, (short) 0);\n        if (scalars[IDX_INPUT_LENGTH] != 320 && !equalsRange(digestScratch, (short) 0, request, digestOffset, DIGEST_LENGTH)) {"}}, "admission bad close digest wrote persistent"},
		{"read-admits-persistent-for-admission", [][2]string{{"        // Produce the chunk again into the admitted RAM span; it is never stored.\n        requireNonPersistentOutput(response, callerWorkspace);", "        // Produce the chunk again into the admitted RAM span; it is never stored.\n        if (scalars[IDX_ACTIVE_METHOD] != 4) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent read span admitted on admission"},
		{"result-admits-empty", [][2]string{{"        if (total <= 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {", "        if (total < 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {"}}, "public prepare refusal 7 wrote persistent"},
		{"result-admits-max-plus-one", [][2]string{{"        if (total <= 0 || total > scalars[IDX_RESPONSE_MAX_LENGTH]) {", "        if (total <= 0 || total > (short) (scalars[IDX_RESPONSE_MAX_LENGTH] + 1)) {"}}, "public prepare refusal 6 wrote persistent"},
		{"descriptor-admits-persistent-for-two-packets", [][2]string{{"                    requireRamSpan(responseBuffer);", "                    if (scalars[IDX_RESULT_PACKET_COUNT] != 2) {\n                        requireRamSpan(responseBuffer);\n                    }"}}, "persistent descriptor span admitted"},
		{"close-admits-persistent-for-envelope", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 1) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on public close"},
		{"close-admits-persistent-for-admission", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 4) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on admission close"},
		{"close-admits-persistent-for-issuer", [][2]string{{"        requireCloseData(requestLength);\n        requireNonPersistentOutput(response, callerWorkspace);", "        requireCloseData(requestLength);\n        if (scalars[IDX_ACTIVE_METHOD] != 3) {\n            requireNonPersistentOutput(response, callerWorkspace);\n        }"}}, "persistent response admitted on issuer close"},
		{"issuer-foreign-write-keeps-handle", [][2]string{{"                    // A refused authenticated APDU invalidates the live handle.\n                    fail(SW_WRONG_STATE);", "                    // A refused authenticated APDU invalidates the live handle.\n                    if (scalars[IDX_METHOD_MODE] == MODE_AUTHENTICATED) {\n                        rejectWithoutClearing(SW_WRONG_STATE);\n                    }\n                    fail(SW_WRONG_STATE);"}}, "issuer foreign refusal retained live handle"},
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
			output, err := mutateRev4Runtime(t, jar, tc.edits)
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
	r := rev4ShapeResult(t, StreamMemoryClearOnDeselect)
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
	output, err := runRev4Shape(t, jar, r)
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
		{"mode-admits-response-only-for-0x20", "codegen/internal/render/stream_modes.go",
			"if method.RequestStream == nil {",
			"if method.RequestStream == nil && method.INS != 0x20 {",
			"TestStreamModeValidation/chunked-response-only"},
		{"authenticated-admits-streamed-result-for-0x70", "codegen/internal/render/stream_authenticated.go",
			"if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" {",
			"if method.IsStream && method.ResponseStream != nil && method.StreamMode == \"\" && method.INS != 0x70 {",
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

// Reachable generated array payload of the real Auth fixture on jCardSim,
// clear-on-reset: the reviewed request-only authenticated-invalidate shape
// (the Auth IDL without its two response streams) against the full Auth IDL
// with the REV4 modes. An independent inventory predicts the delta: one 2 B
// mode scalar in RAM; in persistent tables two more INS bases, two more
// direction bytes, two more five-short limit rows and one mode byte per
// streamed method; the 2048 B workspace is unchanged. Object headers,
// provider/JCRE arrays, Signature or MessageDigest state and reference widths
// are excluded. This is a generator payload, not a whole-card RAM figure.
func TestStreamModesAllocationPayload(t *testing.T) {
	jar := simulatorJar(t)
	measure := func(s *Schema) (transient, persistent, workspace int, output string) {
		r, err := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.bsim", JavaOptions{StreamMemory: StreamMemoryClearOnReset})
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
	requestOnly := authWithModes(t)
	delete(requestOnly.Methods, "buildProvisioningEnvelopeV3")
	delete(requestOnly.Methods, "signAdmissionV1")
	streamed := 0
	for name, method := range requestOnly.Methods {
		method.StreamMode = ""
		if method.HasStream() {
			streamed++
		}
		_ = name
	}
	baseT, baseP, baseW, baseOut := measure(requestOnly)
	modesT, modesP, modesW, modesOut := measure(authWithModes(t))
	streamed += 2
	wantP := baseP + 2 + 2 + 2*5*2 + streamed
	t.Logf("authenticated-invalidate request-only Auth: transient=%d B persistent=%d B workspace=%d B\n%s", baseT, baseP, baseW, baseOut)
	t.Logf("REV4 modes full Auth: transient=%d B persistent=%d B workspace=%d B (%d streamed methods)\n%s", modesT, modesP, modesW, streamed, modesOut)
	if modesT != baseT+2 || modesP != wantP || modesW != 2048 || baseW != 2048 {
		t.Fatalf("payload delta: base %d/%d/%d, modes %d/%d/%d, predicted persistent %d", baseT, baseP, baseW, modesT, modesP, modesW, wantP)
	}
}

// The converter, not javac, decides Java Card Classic compatibility: the mode
// runtime and a fixture using every mode callback (Signature.update included)
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
			r := rev4ShapeResult(t, memory)
			root := t.TempDir()
			sourceDir := filepath.Join(root, "src", "io", "jcrpc", "rev4shape", "server")
			for name, source := range map[string][]byte{
				r.TransportName + ".java": r.TransportSource, r.SkeletonName + ".java": r.SkeletonSource,
				r.StreamEndpointName + ".java": r.StreamEndpointSource, r.StreamRuntimeName + ".java": r.StreamRuntimeSource,
				r.StreamAPDUAdapterName + ".java": r.StreamAPDUAdapterSource, "Rev4ShapeCAPApplet.java": []byte(readTestdata(t, "Rev4ShapeCAPApplet.java")),
			} {
				writeTestFile(t, filepath.Join(sourceDir, name), source)
			}
			buildXML := fmt.Sprintf(`<project name="stream-modes-cap" default="cap">
    <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/>
    <target name="cap">
        <javacard>
            <cap jckit="%s" sources="%s" package="io.jcrpc.rev4shape.server" aid="F000000104" version="1.0" ints="true" output="%s">
                <applet class="io.jcrpc.rev4shape.server.Rev4ShapeCAPApplet" aid="F00000010401"/>
            </cap>
        </javacard>
    </target>
</project>
`, filepath.ToSlash(jar), filepath.ToSlash(kit), filepath.ToSlash(filepath.Join(root, "src")), filepath.ToSlash(filepath.Join(root, "rev4shape.cap")))
			writeTestFile(t, filepath.Join(root, "build.xml"), []byte(buildXML))
			command := exec.Command(ant, "-f", filepath.Join(root, "build.xml"), "cap")
			command.Dir = root
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("CAP conversion failed: %v\n%s", err, output)
			}
			info, err := os.Stat(filepath.Join(root, "rev4shape.cap"))
			if err != nil || info.Size() == 0 {
				t.Fatalf("CAP output missing: %v", err)
			}
			t.Logf("verified CAP ZIP=%d B\n%s", info.Size(), output)
		})
	}
}
