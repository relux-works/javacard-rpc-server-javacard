package codegen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Generated source witnesses use Plugin.Generate, not a parallel model of Java
// execution. The fixture freezes widths/routing independently; JVM semantics,
// APDU transmission and CAP conversion remain separate release-lane evidence.
func ordinaryWriterSchema() *Schema {
	s := &Schema{Applet: Applet{Name: "WriterDemo", AID: "A000000001", CLA: 0x80}, Methods: map[string]*Method{}}
	for i, row := range []struct {
		name  string
		width int
	}{
		{"getAuthenticationIdentity", 127}, {"getAuthAppletInfo", 13}, {"getIssuer190", 190}, {"getIssuer177", 177},
	} {
		s.Methods[row.name] = &Method{Name: row.name, INS: byte(i + 1), Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeBytesFixed, FixedLength: row.width}}}}
	}
	for i, typ := range []FieldType{FieldTypeU8, FieldTypeBool, FieldTypeU16, FieldTypeU32} {
		name := fmt.Sprintf("scalar%d", i)
		s.Methods[name] = &Method{Name: name, INS: byte(5 + i), Response: &Message{Fields: []Field{{Name: "result", Type: typ}}}}
	}
	s.Methods["clear"] = &Method{Name: "clear", INS: 9}
	s.Methods["echo"] = &Method{Name: "echo", INS: 10, Request: &Message{Fields: []Field{{Name: "prefix", Type: FieldTypeU16}, {Name: "payload", Type: FieldTypeBytes}}}, Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeBytes}}}}
	s.Methods["typed"] = &Method{Name: "typed", INS: 11, Request: &Message{Fields: []Field{{Name: "first", Type: FieldTypeU16}, {Name: "second", Type: FieldTypeU32}}}, Response: &Message{Fields: []Field{{Name: "result", Type: FieldTypeU32}}}}
	return s
}

// Fixture overrides must match every generated ordinary callback's return and
// parameter types. This catches source API migration mistakes without a JVM;
// it is deliberately not a Java compiler or a behavior check.
func TestOrdinaryOutputSpanFixtureSourceSignatures(t *testing.T) {
	b, err := os.ReadFile("testdata/OrdinaryOutputSpanHarness.java")
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(returnType, params string) string {
		var types []string
		for _, param := range strings.Split(params, ",") {
			fields := strings.Fields(param)
			if len(fields) > 0 {
				types = append(types, fields[0])
			}
		}
		return returnType + "(" + strings.Join(types, ",") + ")"
	}
	callbacks := regexp.MustCompile(`protected (?:abstract )?(\w+(?:\[\])?) (on\w+)\(([^)]*)\)`)
	overrides := map[string]string{}
	for _, match := range callbacks.FindAllStringSubmatch(string(b), -1) {
		overrides[match[2]] = normalize(match[1], match[3])
	}
	declarations := callbacks.FindAllStringSubmatch(string(writerResult(t).SkeletonSource), -1)
	if len(declarations) != 11 || len(overrides) != 11 {
		t.Fatal("incomplete callback fixture")
	}
	for _, match := range declarations {
		if want := normalize(match[1], match[3]); overrides[match[2]] != want {
			t.Errorf("%s: fixture %s, generated %s", match[2], overrides[match[2]], want)
		}
	}
}

func writerResult(t *testing.T) *JavaGenerationResult {
	t.Helper()
	r, e := GenerateJavaSkeleton(ordinaryWriterSchema(), "io.jcrpc.writer")
	if e != nil {
		t.Fatal(e)
	}
	return r
}

// This source check establishes allocation-free generated ordinary routing and
// decoding on the frozen source shape. It cannot enforce behavior of subclasses.
func TestOrdinaryOutputSpanSourceContract(t *testing.T) {
	r := writerResult(t)
	src := string(r.SkeletonSource)
	for _, token := range []string{
		"public final short dispatchTo(byte ins, byte p1, byte p2,",
		"checkWindow(requestData, requestOffset, requestLength);",
		"checkWindow(output, outputOffset, outputCapacity);",
		"offset > buffer.length || length > buffer.length - offset",
		"short first = readU16(requestData, requestOffset + 0);",
		"int second = readU32(requestData, requestOffset + 2);",
		"short payloadLength = (short) (requestLength - 2);",
		"onEcho(prefix, requestData, payloadOffset, payloadLength, output, outputOffset, outputCapacity)",
		"if (requestLength != 6)",
		"if (produced < 0 || produced > outputCapacity)",
		"dstOff - srcOff < len",
	} {
		if !strings.Contains(src, token) {
			t.Errorf("missing source contract %q", token)
		}
	}
	for _, row := range []struct {
		name  string
		width int
	}{{"GetAuthenticationIdentity", 127}, {"GetAuthAppletInfo", 13}, {"GetIssuer190", 190}, {"GetIssuer177", 177}} {
		body := javaMethodBody(t, src, "handle"+row.name)
		gate := fmt.Sprintf("if (outputCapacity < %d)", row.width)
		call := fmt.Sprintf("on%s(output, outputOffset, (short) %d)", row.name, row.width)
		if strings.Index(body, gate) < 0 || strings.Index(body, gate) > strings.Index(body, call) || !strings.Contains(body, fmt.Sprintf("if (produced != %d)", row.width)) {
			t.Errorf("capacity/callback/width wiring for %s", row.name)
		}
	}
	for _, name := range []string{"dispatchTo", "handleGetAuthenticationIdentity", "handleGetAuthAppletInfo", "handleGetIssuer190", "handleGetIssuer177", "handleScalar0", "handleScalar1", "handleScalar2", "handleScalar3", "handleClear", "handleEcho", "handleTyped"} {
		if strings.Contains(javaMethodBody(t, src, name), "new ") {
			t.Errorf("ordinary path allocates: %s", name)
		}
	}
	for _, token := range []string{"byte[] dispatch(", "abstract byte[] on", "slice(", "this.output", "this.request", "Object[]"} {
		if strings.Contains(src, token) {
			t.Errorf("forbidden ordinary source shape %q", token)
		}
	}
	// Schema carries typed fields, so assertions really see a decoded request.
	typed := javaMethodBody(t, src, "handleTyped")
	if strings.Index(typed, "int second =") > strings.Index(typed, "onTyped(") {
		t.Fatal("typed input decoded after callback")
	}
}

// Bounded control: the source checker must reject a known missing width guard.
// A behavior change that keeps tokens is covered by the JVM mutation suite below,
// explicitly NOT by this control; no source check is labeled behavioral proof.
func TestOrdinaryOutputSpanSourceControl(t *testing.T) {
	src := string(writerResult(t).SkeletonSource)
	hasGuard := func(s string) bool {
		return strings.Contains(javaMethodBody(t, s, "handleGetAuthenticationIdentity"), "if (produced != 127)")
	}
	if !hasGuard(src) {
		t.Fatal("valid control failed")
	}
	mutant := strings.Replace(src, "if (produced != 127)", "if (produced != 127 && produced != 126)", 1)
	// The exact guard, including its closing parenthesis, detects this narrowing.
	if hasGuard(mutant) {
		t.Fatal("source gate admitted 126-byte narrowing control")
	}
}

// JVM claim: generated dispatchTo validates windows, widths and produced lengths
// before a caller can send; valid fixed/scalar/void wire and borrowed overlap are
// exercised. Stub memory is JVM storage, not physical APDU/heap/NVM evidence.
func TestGeneratedOrdinaryOutputSpanBehavior(t *testing.T) {
	output, e := runWriterJava(t, writerResult(t))
	if e != nil {
		t.Fatalf("writer harness: %v\n%s", e, output)
	}
}

// Each guard stays present and admits one neighboring invalid value. The token
// preservation mutant retains the exact width guard but bypasses it for 126;
// the same behavioral harness, not a source-token checker, must kill it.
func TestGeneratedOrdinaryOutputNarrowingMutants(t *testing.T) {
	for _, m := range []struct{ name, from, to, witness string }{
		{"fixed-126", "if (produced != 127)", "if (produced != 127 && produced != 126)", "testProducedLength"},
		{"fixed-token-bypass", "if (produced != 127)", "if (produced == 126) return produced;\n        if (produced != 127)", "testProducedLength"},
		{"capacity-126", "if (outputCapacity < 127)", "if (outputCapacity < 127 && outputCapacity != 126)", "testInsufficientCapacity"},
		{"negative-produced", "produced < 0 || produced > outputCapacity", "(produced < 0 && produced != -1) || produced > outputCapacity", "testVariableProducedLength"},
		{"capacity-plus-one", "produced < 0 || produced > outputCapacity", "produced < 0 || (produced > outputCapacity && produced != outputCapacity + 1)", "testVariableProducedLength"},
		{"window-plus-one", "length > buffer.length - offset", "(length > buffer.length - offset && length != buffer.length - offset + 1)", "testInvalidWindows"},
		{"request-seven", "if (requestLength != 6)", "if (requestLength != 6 && requestLength != 7)", "testRequestAndRouting"},
		{"unknown-7f", "default:\n                throw statusWordFailure(SW_INS_NOT_SUPPORTED);", "case (byte)0x7F: return (short)0;\n            default:\n                throw statusWordFailure(SW_INS_NOT_SUPPORTED);", "testRequestAndRouting"},
		{"overlap-one", "dstOff - srcOff < len", "dstOff - srcOff < len && dstOff - srcOff != 1", "testOverlap"},
		{"pack-bytes-one-past", "srcLen > dst.length - dstOff", "(srcLen > dst.length - dstOff && !(dstOff == 132 && srcLen == 2))", "testInvalidWindows"},
		{"pack-u16-one-past", "2 > buf.length - off", "(2 > buf.length - off && off != 132)", "testInvalidWindows"},
		{"pack-u32-one-past", "4 > buf.length - off", "(4 > buf.length - off && off != 130)", "testInvalidWindows"},
	} {
		t.Run(m.name, func(t *testing.T) {
			r := writerResult(t)
			src := string(r.SkeletonSource)
			if !strings.Contains(src, m.from) {
				t.Fatal("missing mutation anchor")
			}
			r.SkeletonSource = []byte(strings.ReplaceAll(src, m.from, m.to))
			output, e := runWriterJava(t, r)
			exitError, isExit := e.(*exec.ExitError)
			if !isExit || exitError.ExitCode() != 1 || !strings.Contains(output, "AssertionError: "+m.witness) {
				t.Fatalf("SURVIVOR or unrelated failure: %v\n%s", e, output)
			}
			t.Logf("killed %s by TestGeneratedOrdinaryOutputSpanBehavior/%s; java exit=%d\n%s", m.name, m.witness, exitError.ExitCode(), strings.TrimSpace(output))
		})
	}
}

// Ownership controls retain all window/width guards and introduce retention only
// for one valid identity127 call. The original fixture must accept the candidate
// and reject each instance/static/component plant at its named runtime assertion;
// arbitrary subclass object graphs remain outside the generated-class witness.
func TestGeneratedOrdinaryOutputReferenceMutants(t *testing.T) {
	for _, m := range []struct{ name, field, store string }{
		{"instance-output-127", "private byte[] retained;", "retained = output;"},
		{"static-output-127", "private static byte[] retained;", "retained = output;"},
		{"component-output-127", "private final byte[][] retained = new byte[1][];", "retained[0] = output;"},
	} {
		t.Run(m.name, func(t *testing.T) {
			r := writerResult(t)
			src := string(r.SkeletonSource)
			fieldAnchor := "private final byte[] empty;"
			storeAnchor := "checkWindow(output, outputOffset, outputCapacity);"
			if strings.Count(src, fieldAnchor) != 1 || strings.Count(src, storeAnchor) != 1 {
				t.Fatal("ownership plant anchor count")
			}
			src = strings.Replace(src, fieldAnchor, fieldAnchor+"\n    "+m.field, 1)
			src = strings.Replace(src, storeAnchor, storeAnchor+"\n        if (ins == INS_GET_AUTHENTICATION_IDENTITY && outputCapacity == 127) { "+m.store+" }", 1)
			r.SkeletonSource = []byte(src)
			output, err := runWriterJava(t, r)
			exitError, isExit := err.(*exec.ExitError)
			if !isExit || exitError.ExitCode() != 1 || !strings.Contains(output, "AssertionError: testNoRetainedReferences") {
				t.Fatalf("ownership survivor or unrelated failure: %v\n%s", err, output)
			}
			t.Logf("killed %s by TestGeneratedOrdinaryOutputSpanBehavior/testNoRetainedReferences; java exit=%d\n%s", m.name, exitError.ExitCode(), strings.TrimSpace(output))
		})
	}
}

func runWriterJava(t *testing.T, r *JavaGenerationResult) (string, error) {
	t.Helper()
	javac, e := exec.LookPath("javac")
	if e != nil {
		t.Skip("javac unavailable")
	}
	java, e := exec.LookPath("java")
	if e != nil {
		t.Skip("java unavailable")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "io", "jcrpc", "writer")
	stub := writeJavaCardJCSystemStub(t, root)
	writeTestFile(t, filepath.Join(dir, r.TransportName+".java"), r.TransportSource)
	writeTestFile(t, filepath.Join(dir, r.SkeletonName+".java"), r.SkeletonSource)
	harness, e := os.ReadFile("testdata/OrdinaryOutputSpanHarness.java")
	if e != nil {
		t.Fatal(e)
	}
	writeTestFile(t, filepath.Join(dir, "OrdinaryOutputSpanHarness.java"), harness)
	output, e := exec.Command(javac, "-d", root, stub, filepath.Join(dir, r.TransportName+".java"), filepath.Join(dir, r.SkeletonName+".java"), filepath.Join(dir, "OrdinaryOutputSpanHarness.java")).CombinedOutput()
	if e != nil {
		return "compile failure: " + string(output), e
	}
	output, e = exec.Command(java, "-cp", root, "io.jcrpc.writer.OrdinaryOutputSpanHarness").CombinedOutput()
	return string(output), e
}

// Actual Auth fixture is a mixed ordinary/stream schema. Its wire widths and
// fixed INS constants are independent input expectations. All other stream
// runtime/adapter bytes are checked against the historical release matrix.
func TestOrdinaryOutputSpanAuthMixedSource(t *testing.T) {
	s, e := ParseFile("testdata/bsim-auth.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := GenerateJavaSkeleton(s, "io.jcrpc.bsim")
	if e != nil {
		t.Fatal(e)
	}
	src := string(r.SkeletonSource)
	for _, row := range []struct {
		name  string
		width int
		ins   byte
	}{
		{"getAuthenticationIdentity", 127, 1}, {"getAuthAppletInfo", 13, 2},
	} {
		if s.Methods[row.name].INS != row.ins || fixedResponseWidth(t, s.Methods[row.name]) != row.width {
			t.Fatal("Auth fixture wire/INS changed")
		}
		body := javaMethodBody(t, src, "handle"+strings.ToUpper(row.name[:1])+row.name[1:])
		if !strings.Contains(body, fmt.Sprintf("if (produced != %d)", row.width)) || strings.Contains(body, "new ") {
			t.Fatal("Auth writer wiring")
		}
	}
	if !strings.Contains(src, "public final short dispatchTo(") || !strings.Contains(src, "public final short dispatchStreamTo(") {
		t.Fatal("mixed ordinary/stream entry points missing")
	}
}
