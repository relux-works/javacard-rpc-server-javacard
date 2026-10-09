package codegen

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func callerWorkspaceSchema() *Schema {
	s := &Schema{Applet: Applet{Name: "WorkspaceDemo", AID: "F000000104", CLA: 0x80}, Methods: map[string]*Method{}}
	for i, name := range []string{"identity", "issuer"} {
		width := 127
		if i == 1 {
			width = 177
		}
		s.Methods[name] = &Method{Name: name, INS: byte(1 + 2*i), Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeBytesFixed, FixedLength: width}}}}
	}
	s.Methods["packed"] = &Method{Name: "packed", INS: 2, Response: &Message{Fields: []Field{{Name: "head", Type: FieldTypeU16}, {Name: "body", Type: FieldTypeBytesFixed, FixedLength: 188}}}}
	s.Methods["scalar"] = &Method{Name: "scalar", INS: 4, Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeU16}}}}
	s.Methods["consume"] = &Method{Name: "consume", INS: 5, Request: &Message{Fields: []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 3}}}}
	s.Methods["upload"] = &Method{Name: "upload", INS: 0x20, Request: &Message{Fields: []Field{{Name: "payload", Type: FieldTypeStream, MaxLength: 300, ChunkSize: 32}}}, Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeBytesFixed, FixedLength: 177}}}}
	s.Methods["download"] = &Method{Name: "download", INS: 0x30, Request: &Message{Fields: []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 3}}}, Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeStream, MaxLength: 300, ChunkSize: 32}}}}
	return s
}
func callerWorkspaceResult(t *testing.T, policy, cleanup string, memory StreamMemory) *JavaGenerationResult {
	t.Helper()
	s := callerWorkspaceSchema()
	s.Applet.StreamWorkspace = policy
	s.Applet.StreamWorkspaceCleanup = cleanup
	r, e := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.workspace", JavaOptions{StreamMemory: memory})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func writeCallerWorkspaceFixture(t *testing.T, root string, r *JavaGenerationResult) []string {
	t.Helper()
	dir := filepath.Join(root, "src", "io", "jcrpc", "workspace")
	var files []string
	for _, f := range []struct {
		name string
		data []byte
	}{{r.SkeletonName, r.SkeletonSource}, {r.TransportName, r.TransportSource}, {r.StreamEndpointName, r.StreamEndpointSource}, {r.StreamRuntimeName, r.StreamRuntimeSource}, {r.StreamAPDUAdapterName, r.StreamAPDUAdapterSource}} {
		p := filepath.Join(dir, f.name+".java")
		writeTestFile(t, p, f.data)
		files = append(files, p)
	}
	for _, name := range []string{"CallerWorkspaceLogic.java", "CallerWorkspaceApplet.java"} {
		b, e := os.ReadFile("testdata/" + name)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, name)
		writeTestFile(t, p, b)
		files = append(files, p)
	}
	return files
}
func runCallerWorkspaceJava(t *testing.T, r *JavaGenerationResult, harness, main string, plants ...[3]string) (string, error) {
	t.Helper()
	jar := simulatorJar(t)
	root := t.TempDir()
	files := writeCallerWorkspaceFixture(t, root, r)
	for _, plant := range plants {
		p := filepath.Join(root, "src", "io", "jcrpc", "workspace", plant[0])
		b, e := os.ReadFile(p)
		if e != nil || !strings.Contains(string(b), plant[1]) {
			t.Fatalf("missing fixture plant anchor: %v", e)
		}
		writeTestFile(t, p, []byte(strings.ReplaceAll(string(b), plant[1], plant[2])))
	}
	b, e := os.ReadFile("testdata/" + harness + ".java")
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, harness+".java")
	writeTestFile(t, p, b)
	files = append(files, p)
	args := append([]string{"-cp", jar, "-d", root}, files...)
	out, e := exec.Command("javac", args...).CombinedOutput()
	if e != nil {
		return "compile: " + string(out), e
	}
	out, e = exec.Command("java", "-cp", root+string(os.PathListSeparator)+jar, "io.jcrpc.workspace."+main).CombinedOutput()
	return string(out), e
}

// Production dispatchTo and dispatchStreamTo execute every callback shape and
// both stream paths with exact identity/nonzero spans. Bounds are JVM+simulator
// arrays and trusted handlers, not a malicious-handler or physical SD proof.
func TestCallerWorkspaceJVM(t *testing.T) {
	for _, policy := range []string{"transient", "persistent"} {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			t.Run(policy+"/"+string(memory), func(t *testing.T) {
				r := callerWorkspaceResult(t, policy, "", memory)
				out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness")
				if e != nil {
					t.Fatalf("%v\n%s", e, out)
				}
				t.Log(out)
			})
		}
	}
	t.Run("persistent/whole-reply-area", func(t *testing.T) {
		r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
		out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness")
		if e != nil {
			t.Fatalf("%v\n%s", e, out)
		}
		t.Log(out)
	})
}

// The actual simulator invokes Applet.process and processIfStream; replies are
// sent only after generated guards accept. This is not physical 133B capacity.
func TestCallerWorkspaceRealSimulator(t *testing.T) {
	r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
	out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceAPDUHarness", "CallerWorkspaceAPDUHarness")
	if e != nil {
		t.Fatalf("%v\n%s", e, out)
	}
	t.Log(out)
}

// Mixed ordinary+stream classes and both cleanup/storage/lifecycle variants
// compile, convert and verify in the real Classic toolchain with ints=true.
// Artifacts are retained when JCRPC_CAP_EVIDENCE_DIR is configured; no install.
func TestCallerWorkspaceClassicCAP(t *testing.T) {
	ant, e := exec.LookPath("ant")
	if e != nil {
		t.Fatal(e)
	}
	jar, kit := os.Getenv("JCRPC_ANT_JAVACARD_JAR"), os.Getenv("JCRPC_JCKIT_DIR")
	if jar == "" || kit == "" {
		t.Skip("set CAP toolchain variables")
	}
	for _, policy := range []string{"transient", "persistent"} {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			for _, cleanup := range []string{"", "whole-reply-area"} {
				if policy == "transient" && cleanup != "" {
					continue
				}
				name := policy + "/" + string(memory) + "/" + cleanup
				t.Run(name, func(t *testing.T) {
					root := t.TempDir()
					writeCallerWorkspaceFixture(t, root, callerWorkspaceResult(t, policy, cleanup, memory))
					capPath := filepath.Join(root, "workspace.cap")
					build := fmt.Sprintf(`<project default="cap"><taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/><target name="cap"><javacard><cap jckit="%s" sources="%s" package="io.jcrpc.workspace" aid="F000000104" version="1.0" ints="true" output="%s"><applet class="io.jcrpc.workspace.CallerWorkspaceApplet" aid="F00000010401"/></cap></javacard></target></project>`, jar, kit, filepath.Join(root, "src"), capPath)
					p := filepath.Join(root, "build.xml")
					writeTestFile(t, p, []byte(build))
					out, e := exec.Command(ant, "-f", p, "cap").CombinedOutput()
					t.Log(string(out))
					if e != nil {
						t.Fatalf("Classic CAP: %v", e)
					}
					b, e := os.ReadFile(capPath)
					if e != nil {
						t.Fatal(e)
					}
					z, e := zip.OpenReader(capPath)
					if e != nil {
						t.Fatal(e)
					}
					defer z.Close()
					components := 0
					for _, f := range z.File {
						if strings.HasSuffix(f.Name, ".cap") {
							components++
						}
					}
					if components < 10 {
						t.Fatal("incomplete CAP")
					}
					t.Logf("CAP components=%d bytes=%d SHA256=%x", components, len(b), sha256.Sum256(b))
					if dir := os.Getenv("JCRPC_CAP_EVIDENCE_DIR"); dir != "" {
						name = strings.ReplaceAll(name, "/", "-")
						writeTestFile(t, filepath.Join(dir, name+".cap"), b)
						writeTestFile(t, filepath.Join(dir, name+".log"), out)
					}
				})
			}
		}
	}
}

// Narrowing guards retain the refusal and admit exactly the stated invalid
// fixture member. Token-preserving plumbing plants execute the same behavioral
// suite, with named assertion/real JVM exit required; setup failure is not a kill.
func TestCallerWorkspaceNarrowingMutants(t *testing.T) {
	for _, m := range []struct{ name, unit, from, to, witness, bound string }{
		{"ordinary-null-empty", "skeleton", "private void checkWindow(byte[] buffer, short offset, short length) {", "private void checkWindow(byte[] buffer, short offset, short length) {\n        if (buffer == null && offset == 0 && length == 0) return;", "testWorkspaceBeforeEffects", "admits null (0,0), preserves remaining window guards"},
		{"ordinary-negative-offset", "skeleton", "buffer == null || offset < 0 || length < 0 ||", "buffer == null || (offset < 0 && offset != -1) || length < 0 ||", "testWorkspaceBeforeEffects", "admits offset -1"},
		{"ordinary-negative-capacity", "skeleton", "buffer == null || offset < 0 || length < 0 ||", "buffer == null || offset < 0 || (length < 0 && length != -1) ||", "testWorkspaceBeforeEffects", "admits capacity -1"},
		{"ordinary-end-plus-one", "skeleton", "length > buffer.length - offset)", "(length > buffer.length - offset && !(buffer.length == 300 && offset == 17 && length == 284)))", "testWorkspaceBeforeEffects", "admits 300B array / offset17 / capacity284"},
		{"ordinary-end-nonzero", "skeleton", "length > buffer.length - offset)", "(length > buffer.length - offset && !(buffer.length == 300 && offset == 300 && length == 1)))", "testWorkspaceBeforeEffects", "admits 300B array / offset300 / capacity1"},
		{"ordinary-outside-offset", "skeleton", "offset > buffer.length || length > buffer.length - offset", "(offset > buffer.length && !(buffer.length == 300 && offset == 301 && length == 0)) || (length > buffer.length - offset && !(buffer.length == 300 && offset == 301 && length == 0))", "testWorkspaceBeforeEffects", "admits offset301/zero on300B array"},
		{"ordinary-overflow-span", "skeleton", "offset > buffer.length || length > buffer.length - offset", "(offset > buffer.length || length > buffer.length - offset) && !(buffer.length == 300 && offset == 32760 && length == 32760)", "testWorkspaceBeforeEffects", "admits the short-sum-overflow geometry32760/32760"},
		{"stream-null-empty", "runtime", "if (callerWorkspace == null || callerWorkspaceOffset < 0 || callerWorkspaceCapacity < 0 ||", "if ((callerWorkspace == null || callerWorkspaceOffset < 0 || callerWorkspaceCapacity < 0 ||", "testWorkspaceBeforeEffects", "admits null0/0 only; normal guard remains"},
		{"stream-negative-offset", "runtime", "callerWorkspaceOffset < 0 ||", "(callerWorkspaceOffset < 0 && callerWorkspaceOffset != -1) ||", "testWorkspaceBeforeEffects", "admits offset -1"},
		{"stream-negative-capacity", "runtime", "callerWorkspaceCapacity < 0 ||", "(callerWorkspaceCapacity < 0 && callerWorkspaceCapacity != -1) ||", "testWorkspaceBeforeEffects", "admits capacity -1"},
		{"stream-end-plus-one", "runtime", "callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset)", "(callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset && !(callerWorkspace.length == 300 && callerWorkspaceOffset == 17 && callerWorkspaceCapacity == 284)))", "testWorkspaceBeforeEffects", "admits offset17/cap284 on300B array"},
		{"stream-end-nonzero", "runtime", "callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset)", "(callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset && !(callerWorkspace.length == 300 && callerWorkspaceOffset == 300 && callerWorkspaceCapacity == 1)))", "testWorkspaceBeforeEffects", "admits offset300/cap1 on300B array"},
		{"stream-outside-offset", "runtime", "callerWorkspaceOffset > callerWorkspace.length ||\n                callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset", "(callerWorkspaceOffset > callerWorkspace.length ||\n                callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset) && !(callerWorkspace.length == 300 && callerWorkspaceOffset == 301 && callerWorkspaceCapacity == 0)", "testWorkspaceBeforeEffects", "admits offset301/zero on300B array"},
		{"stream-overflow-span", "runtime", "callerWorkspaceOffset > callerWorkspace.length ||\n                callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset", "(callerWorkspaceOffset > callerWorkspace.length ||\n                callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset) && !(callerWorkspace.length == 300 && callerWorkspaceOffset == 32760 && callerWorkspaceCapacity == 32760)", "testWorkspaceBeforeEffects", "admits the short-sum-overflow geometry32760/32760"},
		{"ordinary-dispatch-wrong-buffer-token", "skeleton", "return handleIdentity(p1, p2, requestData, requestOffset, requestLength, output, outputOffset, outputCapacity, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "return handleIdentity(p1, p2, requestData, requestOffset, requestLength, output, outputOffset, outputCapacity, callerWorkspaceCapacity == 260 ? output : callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "testExactWorkspaceIdentity", "keeps callerWorkspace tokens and guards, substitutes output on identity/cap260"},
		{"ordinary-callback-wrong-offset-token", "skeleton", "onIdentity(output, outputOffset, (short) 127, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity)", "onIdentity(output, outputOffset, (short) 127, callerWorkspace, (short)(callerWorkspaceOffset + (callerWorkspaceCapacity == 260 ? 1 : 0)), callerWorkspaceCapacity)", "testExactWorkspaceIdentity", "shifts scratch offset by1 at identity/cap260"},
		{"ordinary-callback-widen-capacity-token", "skeleton", "onIdentity(output, outputOffset, (short) 127, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity)", "onIdentity(output, outputOffset, (short) 127, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity == 260 ? (short)callerWorkspace.length : callerWorkspaceCapacity)", "testExactWorkspaceIdentity", "uses full array length only at identity/cap260"},
		{"stream-dispatch-wrong-buffer-token", "skeleton", "responseBuffer, responseOffset, responseCapacity,\n                    callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "responseBuffer, responseOffset, responseCapacity,\n                    callerWorkspaceCapacity == 260 ? responseBuffer : callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "testWorkspaceBounds", "keeps triple tokens; response reconstruction is too small and refused before callback"},
		{"stream-close-execute-wrong-buffer-token", "runtime", "workspace, (short) 0, outputCapacity,\n                callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "workspace, (short) 0, outputCapacity,\n                hasRequestStream() ? workspace : callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "testExactWorkspaceIdentity", "CLOSE_WRITE receives owned bulk instead of actual entry scratch"},
		{"stream-response-execute-wrong-buffer-token", "runtime", "workspace, (short) 0, outputCapacity,\n                callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "workspace, (short) 0, outputCapacity,\n                hasRequestStream() ? callerWorkspace : workspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "testExactWorkspaceIdentity", "response-only receives owned bulk instead of actual entry scratch"},
		{"stream-callback-wrong-offset-token", "skeleton", "return onUploadStream(input, inputOffset, inputLength,\n                        output, outputOffset, outputCapacity, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "return onUploadStream(input, inputOffset, inputLength,\n                        output, outputOffset, outputCapacity, callerWorkspace, (short)(callerWorkspaceOffset + (callerWorkspaceCapacity == 260 ? 1 : 0)), callerWorkspaceCapacity);", "testExactWorkspaceIdentity", "stream callback offset is shifted on upload/cap260 only"},
		{"stream-response-callback-widen-token", "skeleton", "return onDownloadStream(input, inputOffset, inputLength,\n                        output, outputOffset, outputCapacity, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "return onDownloadStream(input, inputOffset, inputLength,\n                        output, outputOffset, outputCapacity, callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity == 260 ? (short)callerWorkspace.length : callerWorkspaceCapacity);", "testExactWorkspaceIdentity", "response-only callback uses array length instead of cap260"},
		{"stream-invalid-clears-token", "runtime", "// Validate borrowed authority before reset cleanup or any session effect.", "// Validate borrowed authority before reset cleanup or any session effect.\n        if (callerWorkspaceCapacity == -1) clearAll();", "testInvalidScratchPreservesPending", "retains exact guard but clears a pending session on negative capacity"},
		{"ordinary-width126-token", "skeleton", "if (produced != 127)", "if (produced == 126) return produced;\n        if (produced != 127)", "testProducedGuard", "retains exact width guard but permits126"},
		{"stream-width176-token", "runtime", "produced != scalars[IDX_EXACT_SHORT_RESPONSE_LENGTH]", "produced != scalars[IDX_EXACT_SHORT_RESPONSE_LENGTH] && produced != 176", "testStreamProducedGuard", "permits one neighboring177B fixed result count176"},
	} {
		t.Run(m.name, func(t *testing.T) {
			r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
			source := &r.SkeletonSource
			if m.unit == "runtime" {
				source = &r.StreamRuntimeSource
			}
			s := string(*source)
			if !strings.Contains(s, m.from) {
				t.Fatal("missing mutant anchor")
			}
			s = strings.Replace(s, m.from, m.to, 1)
			if m.name == "stream-null-empty" {
				s = strings.Replace(s, "callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset) {", "callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset) && !(callerWorkspace == null && callerWorkspaceOffset == 0 && callerWorkspaceCapacity == 0)) {", 1)
			}
			*source = []byte(s)
			out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness")
			x, ok := e.(*exec.ExitError)
			// A pipeline wrong-buffer may fail preflight; the named positive group
			// turns that unexpected production refusal into an assertion failure.
			if m.name == "stream-dispatch-wrong-buffer-token" {
				m.witness = "testOverlapLiveness"
			}
			switch m.name {
			case "stream-null-empty":
				m.witness = "testWorkspaceBounds null status"
			case "stream-negative-capacity":
				m.witness = "testWorkspaceBounds negative-capacity status"
			case "stream-end-nonzero":
				m.witness = "testWorkspaceBounds end-nonzero status"
			case "stream-outside-offset":
				m.witness = "testWorkspaceBounds outside-offset status"
			}
			if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: "+m.witness) {
				t.Fatalf("SURVIVOR (no named behavioral failure) or unrelated failure; bound=%s; %v\n%s", m.bound, e, out)
			}
			t.Logf("mutant=%s narrows=%s killed-by=TestCallerWorkspaceJVM/%s java-exit=%d\n%s", m.name, m.bound, m.witness, x.ExitCode(), out)
		})
	}
}

// Host reflection catches generated instance/static/object-component retention
// after return. It excludes arbitrary handler internals and SD/JCRE machinery.
func TestCallerWorkspaceReferenceMutants(t *testing.T) {
	for _, unit := range []string{"skeleton", "runtime"} {
		for _, shape := range []string{"instance", "static", "component"} {
			t.Run(unit+"/"+shape, func(t *testing.T) {
				r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
				source := &r.SkeletonSource
				anchor := "private final byte[] empty;"
				store := "checkWindow(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);"
				if unit == "runtime" {
					source = &r.StreamRuntimeSource
					anchor = "private final byte[] workspace;"
					store = "validateRange(responseBuffer, responseOffset, responseCapacity);"
				}
				s := string(*source)
				decl := "private byte[] retainedCaller;"
				assign := "retainedCaller = callerWorkspace;"
				if shape == "static" {
					decl = "private static byte[] retainedCaller;"
				}
				if shape == "component" {
					decl = "private final Object[] retainedCaller = new Object[1];"
					assign = "retainedCaller[0] = callerWorkspace;"
				}
				if strings.Count(s, anchor) != 1 || strings.Count(s, store) != 1 {
					t.Fatal("retention anchor count")
				}
				s = strings.Replace(s, anchor, anchor+"\n    "+decl, 1)
				s = strings.Replace(s, store, store+"\n            if (callerWorkspaceCapacity == 260) { "+assign+" }", 1)
				*source = []byte(s)
				out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness")
				x, ok := e.(*exec.ExitError)
				if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: testNoBorrowedReferences") {
					t.Fatalf("SURVIVOR or unrelated failure: %v\n%s", e, out)
				}
				t.Logf("mutant=%s/%s retains scratch only for cap260 killed-by=TestCallerWorkspaceJVM/testNoBorrowedReferences java-exit=%d\n%s", unit, shape, x.ExitCode(), out)
			})
		}
	}
}

// Generated API membership comes from the fixture's IDL, independently of the
// renderer. Source checks see flat signatures/wiring, not arbitrary Java graphs;
// token-preserving behavioral mutants qualify their important blind spot.
func TestCallerWorkspaceSourceContract(t *testing.T) {
	s := callerWorkspaceSchema()
	r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
	src := string(r.SkeletonSource)
	callbacks := regexp.MustCompile(`protected abstract (?:short|void) (on\w+)\(([^)]*)\);`).FindAllStringSubmatch(src, -1)
	if len(callbacks) != len(s.Methods) {
		t.Fatalf("API coverage %d of %d", len(callbacks), len(s.Methods))
	}
	seen := map[string]bool{}
	for _, c := range callbacks {
		suffix := "byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity"
		normalized := strings.Join(strings.Fields(c[2]), " ")
		if !strings.HasSuffix(normalized, suffix) {
			t.Fatalf("missing trailing workspace: %s", c[1])
		}
		seen[c[1]] = true
	}
	for name, m := range s.Methods {
		callback := "on" + strings.ToUpper(name[:1]) + name[1:]
		if m.HasStream() {
			callback += "Stream"
		}
		if !seen[callback] {
			t.Fatalf("IDL callback missing %s", callback)
		}
	}
	dispatch := javaMethodBody(t, src, "dispatchTo")
	if strings.Index(dispatch, "checkWindow(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);") < 0 || strings.Index(dispatch, "checkWindow(callerWorkspace,") > strings.Index(dispatch, "switch (ins)") {
		t.Fatal("ordinary pre-effect scratch guard missing")
	}
	rt := string(r.StreamRuntimeSource)
	entry := javaMethodBody(t, rt, "dispatch")
	if strings.Index(entry, "callerWorkspace == null") < 0 || strings.Index(entry, "callerWorkspace == null") > strings.Index(entry, "try {") {
		t.Fatal("scratch guard must precede reset/exception cleanup boundary")
	}
	for _, text := range []string{src, rt, string(r.StreamEndpointSource)} {
		for _, bad := range []string{"this.callerWorkspace", "static byte[] callerWorkspace", "ThreadLocal", "apdu.getBuffer()"} {
			if strings.Contains(text, bad) {
				t.Fatalf("forbidden caller storage/lookup %s", bad)
			}
		}
	}
	if strings.Count(src, "public final short dispatchTo(") != 1 || strings.Count(src, "public final short dispatchStreamTo(") != 1 {
		t.Fatal("compatibility shim or missing dispatcher")
	}
	if !strings.Contains(string(r.StreamAPDUAdapterSource), "apduBuffer,\n                    (short) 0,\n                    (short) apduBuffer.length") {
		t.Fatal("adapter must pass its actual command-local APDU span")
	}
	t.Logf("API coverage: %d of %d IDL callback rows driven through Plugin.Generate", len(callbacks), len(s.Methods))
}

// The test-handler phase guards must reject 133B and the immediate predecessor
// of 196/260. Each retained predicate admits only its stated neighboring member.
// They establish fixture minima sensitivity, not Auth crypto implementation.
func TestCallerWorkspaceConsumerMinimumMutants(t *testing.T) {
	for _, capacity := range []int{133, 195, 259} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
			a := [3]string{"CallerWorkspaceLogic.java", "capacity < required", fmt.Sprintf("capacity < required && capacity != %d", capacity)}
			b := [3]string{"CallerWorkspaceLogic.java", "callerWorkspaceCapacity < required", fmt.Sprintf("callerWorkspaceCapacity < required && callerWorkspaceCapacity != %d", capacity)}
			out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness", a, b)
			x, ok := e.(*exec.ExitError)
			if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: testBusinessMinimum admitted") {
				t.Fatalf("SURVIVOR or unrelated phase failure: %v\n%s", e, out)
			}
			t.Logf("mutant=consumer-minimum-%d permits that capacity below phase minimum killed-by=TestCallerWorkspaceJVM/testBusinessMinima java-exit=%d\n%s", capacity, x.ExitCode(), out)
		})
	}
}

func runCallerWorkspaceAdapterJava(t *testing.T, r *JavaGenerationResult) (string, error) {
	t.Helper()
	root := t.TempDir()
	paths := writeCallerWorkspaceFixture(t, root, r)
	var sources []string
	for _, p := range paths {
		if !strings.HasSuffix(p, "CallerWorkspaceApplet.java") {
			sources = append(sources, p)
		}
	}
	for name, src := range map[string]string{"javacard/framework/JCSystem.java": apduJCSystemStub, "javacard/framework/APDU.java": fragmentedAPDUStub, "javacard/framework/ISOException.java": apduISOExceptionStub, "javacard/framework/ISO7816.java": apduISO7816Stub, "javacard/security/MessageDigest.java": apduMessageDigestStub, "io/jcrpc/workspace/AdapterWorkspaceHarness.java": callerWorkspaceAdapterHarness} {
		p := filepath.Join(root, name)
		writeTestFile(t, p, []byte(src))
		sources = append(sources, p)
	}
	out, e := exec.Command("javac", append([]string{"-d", root}, sources...)...).CombinedOutput()
	if e != nil {
		return "compile: " + string(out), e
	}
	out, e = exec.Command("java", "-cp", root, "io.jcrpc.workspace.AdapterWorkspaceHarness").CombinedOutput()
	return string(out), e
}

// Real generated processIfStream forwards the current APDU array in both
// execution paths, including fragmented receive. The APDU/JCRE objects here are
// bounded JVM stubs; actual simulator/send qualification remains a separate test.
func TestCallerWorkspaceAdapterBehavior(t *testing.T) {
	r := callerWorkspaceResult(t, "persistent", "", StreamMemoryClearOnDeselect)
	out, e := runCallerWorkspaceAdapterJava(t, r)
	if e != nil {
		t.Fatalf("%v\n%s", e, out)
	}
	t.Log(out)
}

// The actual adapter's APDU tokens remain in each plant. Forwarding a 255B I/O
// array, shifting the span or narrowing capacity must fail its named positive
// production witness, not compile failure or an unclassified JVM exception.
func TestCallerWorkspaceAdapterMutants(t *testing.T) {
	for _, m := range []struct{ name, from, to, bound string }{
		{"adapter-wrong-buffer-token", "apduBuffer,\n                    (short) 0,\n                    (short) apduBuffer.length", "apduBuffer.length == 260 ? ioScratch : apduBuffer,\n                    (short) 0,\n                    (short) (apduBuffer.length == 260 ? ioScratch.length : apduBuffer.length)", "reconstructs caller workspace from255B I/O for260B APDU"},
		{"adapter-wrong-offset-token", "apduBuffer,\n                    (short) 0,\n                    (short) apduBuffer.length", "apduBuffer,\n                    (short) (apduBuffer.length == 260 ? 1 : 0),\n                    (short) apduBuffer.length", "shifts current260B APDU offset by1"},
		{"adapter-capacity259-token", "(short) apduBuffer.length);", "(short) (apduBuffer.length == 260 ? 259 : apduBuffer.length));", "narrows actual260B capacity to259"},
	} {
		t.Run(m.name, func(t *testing.T) {
			r := callerWorkspaceResult(t, "persistent", "", StreamMemoryClearOnDeselect)
			s := string(r.StreamAPDUAdapterSource)
			if strings.Count(s, m.from) != 1 {
				t.Fatal("adapter mutant anchor")
			}
			r.StreamAPDUAdapterSource = []byte(strings.Replace(s, m.from, m.to, 1))
			out, e := runCallerWorkspaceAdapterJava(t, r)
			x, ok := e.(*exec.ExitError)
			if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: testAdapterCallerWorkspace") {
				t.Fatalf("SURVIVOR or unrelated adapter failure: %v\n%s", e, out)
			}
			t.Logf("mutant=%s changes=%s killed-by=TestCallerWorkspaceAdapterBehavior/testAdapterCallerWorkspace java-exit=%d\n%s", m.name, m.bound, x.ExitCode(), out)
		})
	}
}

const callerWorkspaceAdapterHarness = `package io.jcrpc.workspace;
import javacard.framework.*;
import java.security.MessageDigest;
import java.lang.reflect.*;
public final class AdapterWorkspaceHarness {
 static class Logic extends CallerWorkspaceLogic {
  byte[] expected;
  protected void probeWorkspace(byte[] b,short o,short c){
   if(b!=expected||o!=0||c!=260)throw new AssertionError("testAdapterCallerWorkspace identity/offset/capacity");super.probeWorkspace(b,o,c);
  }
 }
 static void call(Logic logic,WorkspaceDemoStreamAPDUAdapter adapter,int ins,int p2,byte[] input,int[] fragments)throws Exception{
  APDU a=new APDU((byte)0x80,(byte)ins,(byte)0,(byte)p2,input,fragments);logic.expected=a.getBuffer();
  try{if(!adapter.processIfStream(a))throw new AssertionError("testAdapterCallerWorkspace fallback");}
  catch(ISOException|WorkspaceDemoSkeleton.StatusWordException e){throw new AssertionError("testAdapterCallerWorkspace unexpected refusal",e);}
  for(Field f:adapter.getClass().getDeclaredFields()){f.setAccessible(true);if(f.get(adapter)==a.getBuffer())throw new AssertionError("testAdapterCallerWorkspace retained");}
 }
 public static void main(String[] args)throws Exception{
  Logic l=new Logic();l.required=260;WorkspaceDemoStreamAPDUAdapter a=new WorkspaceDemoStreamAPDUAdapter(l);byte[] input={11,22,33};
  call(l,a,0x20,1,input,new int[]{1,1,1});byte[] close=new byte[34];close[1]=3;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(input),0,close,2,32);
  call(l,a,0x21,0,close,new int[]{2,16,16});if(l.calls!=1)throw new AssertionError("testAdapterCallerWorkspace close");
  call(l,a,0x30,0,input,new int[]{1,2});if(l.calls!=2)throw new AssertionError("testAdapterCallerWorkspace response-only");
  System.out.println("actual generated adapter current-APDU identity/offset/capacity passed on bounded JCRE stubs");
 }
}
`

// A token-preserving guard relocation still refuses the invalid scratch, but
// wrongly wipes reset residue first. The controlled post-reset fixture checks
// this narrower pre-effect property; retained simulator tests prove real reset.
func TestCallerWorkspaceResetGuardMutant(t *testing.T) {
	r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
	s := string(r.StreamRuntimeSource)
	guard := `        if (callerWorkspace == null || callerWorkspaceOffset < 0 || callerWorkspaceCapacity < 0 ||
                callerWorkspaceOffset > callerWorkspace.length ||
                callerWorkspaceCapacity > callerWorkspace.length - callerWorkspaceOffset) {
            rejectWithoutClearing(SW_WRONG_LENGTH);
        }
`
	anchor := "            validateRange(requestBuffer, requestOffset, requestLength);"
	if strings.Count(s, guard) != 1 || strings.Count(s, anchor) != 1 {
		t.Fatal("reset guard anchor")
	}
	s = strings.Replace(s, guard, "", 1)
	s = strings.Replace(s, anchor, guard+anchor, 1)
	r.StreamRuntimeSource = []byte(s)
	out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness")
	x, ok := e.(*exec.ExitError)
	if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: testInvalidScratchPreservesResetResidue") {
		t.Fatalf("SURVIVOR or unrelated reset failure: %v\n%s", e, out)
	}
	t.Logf("mutant=guard-after-reset-token admits reset wipe before invalid-scratch refusal killed-by=TestCallerWorkspaceJVM/testInvalidScratchPreservesResetResidue java-exit=%d\n%s", x.ExitCode(), out)
}

// Trusted handlers, not the generic framework, own last-consumer/output ordering.
// These fixture plants keep checks/tokens and change the ordering of real stores.
// The same production dispatch suite must expose aliased input/output damage.
func TestCallerWorkspaceLivenessMutants(t *testing.T) {
	for _, kind := range []string{"input-last-consumer", "output-final-read"} {
		t.Run(kind, func(t *testing.T) {
			r := callerWorkspaceResult(t, "persistent", "whole-reply-area", StreamMemoryClearOnReset)
			var plants [][3]string
			witness := "testOverlapLiveness"
			if kind == "input-last-consumer" {
				plants = [][3]string{
					{"CallerWorkspaceLogic.java", "// The third byte is the last consumer: don't overwrite aliased scratch yet.", "probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);\n        // The third byte is the last consumer: don't overwrite aliased scratch yet."},
					{"CallerWorkspaceLogic.java", "throw statusWordFailure((short) 0x6A80);\n        }\n        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);", "throw statusWordFailure((short) 0x6A80);\n        }"},
				}
			} else {
				plants = [][3]string{{"CallerWorkspaceLogic.java", "probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);\n        return reply(output, outputOffset, outputCapacity, (byte) 6);", "short produced = reply(output, outputOffset, outputCapacity, (byte) 6);\n        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);\n        return produced;"}}
				witness = "testOverlapOutputLifetime"
			}
			out, e := runCallerWorkspaceJava(t, r, "CallerWorkspaceHarness", "CallerWorkspaceHarness", plants...)
			x, ok := e.(*exec.ExitError)
			if !ok || x.ExitCode() != 1 || !strings.Contains(out, "AssertionError: "+witness) {
				t.Fatalf("SURVIVOR or unrelated liveness failure: %v\n%s", e, out)
			}
			t.Logf("mutant=%s changes trusted ordering only killed-by=TestCallerWorkspaceJVM/%s java-exit=%d\n%s", kind, witness, x.ExitCode(), out)
		})
	}
}
