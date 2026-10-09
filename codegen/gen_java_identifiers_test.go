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

type ordinaryIdentifierCase struct {
	name              string
	request, response []Field
}

// The first six rows retain the reviewer's exact requests/responses and names.
// Additional rows exercise the same scope failure class, not new IDL restrictions.
// Normative facade identifier grammar: ^[A-Za-z][A-Za-z0-9_]*$, validator.go
// SHA256 f25d1d2443dcfacdd58980bfb803325a524ebb39e61c2d310b111670e6c1a5fc.
func ordinaryIdentifierCases() []ordinaryIdentifierCase {
	scalar := []Field{{Name: "answer", Type: FieldTypeU8}}
	fixed := []Field{{Name: "answer", Type: FieldTypeBytesFixed, FixedLength: 1}}
	rows := []ordinaryIdentifierCase{
		{"positive-value", []Field{{Name: "value", Type: FieldTypeU8}}, scalar},
		{"request-output", []Field{{Name: "output", Type: FieldTypeU8}}, nil},
		{"request-produced", []Field{{Name: "produced", Type: FieldTypeU8}}, fixed},
		{"request-result", []Field{{Name: "result", Type: FieldTypeU8}}, scalar},
		{"positive-borrowed", []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "marker", Type: FieldTypeU8}}, nil},
		{"borrowed-suffix", []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadOffset", Type: FieldTypeU8}}, nil},
	}
	for _, name := range []string{"p1", "p2", "requestData", "requestOffset", "requestLength", "outputOffset", "outputCapacity", "value"} {
		rows = append(rows, ordinaryIdentifierCase{"window-" + name, []Field{{Name: name, Type: FieldTypeU8}}, fixed})
	}
	rows = append(rows,
		ordinaryIdentifierCase{"p1-p2-fields", []Field{{Name: "p1", Type: FieldTypeU8, Location: ParameterLocationP1}, {Name: "p2", Type: FieldTypeBool, Location: ParameterLocationP2}}, scalar},
		ordinaryIdentifierCase{"borrowed-length", []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadLength", Type: FieldTypeU8}}, fixed},
		ordinaryIdentifierCase{"suffix-chain", []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadOffset", Type: FieldTypeU8}, {Name: "payloadOffset_1", Type: FieldTypeU8}, {Name: "payloadLength", Type: FieldTypeU8}, {Name: "payloadLength_1", Type: FieldTypeU8}}, fixed},
		ordinaryIdentifierCase{"multiple-borrowed", []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadOffset", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadLength", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "payloadOffsetOffset", Type: FieldTypeU8}, {Name: "payloadLengthLength", Type: FieldTypeU8}}, fixed},
		ordinaryIdentifierCase{"variable-writer", []Field{{Name: "produced", Type: FieldTypeU8}, {Name: "output", Type: FieldTypeBytes}}, []Field{{Name: "answer", Type: FieldTypeBytes}}},
		ordinaryIdentifierCase{"packed-writer", []Field{{Name: "output", Type: FieldTypeU8}, {Name: "outputCapacity", Type: FieldTypeU16}}, []Field{{Name: "first", Type: FieldTypeU8}, {Name: "second", Type: FieldTypeU16}}},
		ordinaryIdentifierCase{"prefix-like", []Field{{Name: "jcrpc_output", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: "jcrpc_outputOffset", Type: FieldTypeU8}, {Name: "output_1", Type: FieldTypeU8}, {Name: "output", Type: FieldTypeU8}, {Name: "output_2", Type: FieldTypeU8}, {Name: "result_1", Type: FieldTypeU8}, {Name: "result", Type: FieldTypeU8}}, scalar},
	)
	for _, typ := range []FieldType{FieldTypeBool, FieldTypeU16, FieldTypeU32} {
		rows = append(rows, ordinaryIdentifierCase{"scalar-" + string(typ), []Field{{Name: "result", Type: FieldTypeU8}}, []Field{{Name: "answer", Type: typ}}})
	}
	return rows
}

func identifierSchema(tc ordinaryIdentifierCase) *Schema {
	return &Schema{Applet: Applet{Name: "Probe", Version: "1.0.0", AID: "F000000123", CLA: 0x80}, Methods: map[string]*Method{"echo": {Name: "echo", INS: 1, Request: &Message{Fields: tc.request}, Response: &Message{Fields: tc.response}}}}
}

func identifierFiles(t *testing.T, tc ordinaryIdentifierCase) ([]pluginapi.File, string) {
	t.Helper()
	files, err := (Plugin{}).Generate(identifierSchema(tc), pluginapi.Options{Namespace: "io.probe"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name, "Skeleton.java") {
			return files, string(f.Data)
		}
	}
	t.Fatal("missing skeleton")
	return nil, ""
}

var javaVariableDeclaration = regexp.MustCompile(`(?:byte\[\]|byte|short|int|boolean)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:=|,|\)|$)`)

// Independent structural check of emitted callback and handler scopes. It sees
// every parameter/local declaration in this renderer's flat ordinary methods;
// it does not parse arbitrary Java, prove compilation, or execute dispatch.
func assertIdentifierScopes(t *testing.T, src string) {
	t.Helper()
	handler := regexp.MustCompile(`private short handleEcho\(([^)]*)\)`).FindStringSubmatch(src)
	callback := regexp.MustCompile(`protected abstract \w+ onEcho\(([^)]*)\)`).FindStringSubmatch(src)
	if len(handler) != 2 || len(callback) != 2 {
		t.Fatal("missing production ordinary scopes")
	}
	for _, scope := range []string{handler[1] + ")\n" + javaMethodBody(t, src, "handleEcho"), callback[1] + ")"} {
		seen := map[string]bool{}
		for _, declaration := range javaVariableDeclaration.FindAllStringSubmatch(scope, -1) {
			name := declaration[1]
			if seen[name] {
				t.Fatalf("generated namespace collision: %s", name)
			}
			seen[name] = true
		}
	}
}

// Plugin.Generate must preserve supported IDL names while emitting distinct
// ordinary parameters/locals. All four rejected rev1 variants and both nearby
// controls use the same production path. JVM compilation is a separate gate.
func TestOrdinaryIdentifierSourceRegression(t *testing.T) {
	for _, tc := range ordinaryIdentifierCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, src := identifierFiles(t, tc)
			assertIdentifierScopes(t, src)
			assertIdentifierCallback(t, tc, src)
		})
	}
}

// Types/order are derived from the input IDL, independently of the renderer's
// name allocator. A unique but reordered or scalar-to-writer API is forbidden.
func assertIdentifierCallback(t *testing.T, tc ordinaryIdentifierCase, src string) {
	t.Helper()
	match := regexp.MustCompile(`protected abstract (\w+) onEcho\(([^)]*)\)`).FindStringSubmatch(src)
	if len(match) != 3 {
		t.Fatal("missing callback")
	}
	var want []string
	for _, f := range tc.request {
		switch f.Type {
		case FieldTypeU8:
			want = append(want, "byte")
		case FieldTypeBool:
			want = append(want, "boolean")
		case FieldTypeU16:
			want = append(want, "short")
		case FieldTypeU32:
			want = append(want, "int")
		default:
			want = append(want, "byte[]", "short", "short")
		}
	}
	returnType := "short"
	if len(tc.response) == 0 {
		returnType = "void"
	} else if len(tc.response) == 1 {
		switch tc.response[0].Type {
		case FieldTypeU8:
			returnType = "byte"
		case FieldTypeBool:
			returnType = "boolean"
		case FieldTypeU16:
			returnType = "short"
		case FieldTypeU32:
			returnType = "int"
		}
	}
	writer := returnType == "short" && !(len(tc.response) == 1 && tc.response[0].Type == FieldTypeU16)
	if writer {
		want = append(want, "byte[]", "short", "short")
	}
	var got []string
	if match[2] != "" {
		for _, p := range strings.Split(match[2], ",") {
			got = append(got, strings.Fields(p)[0])
		}
	}
	if match[1] != returnType || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("callback types/order changed: %s(%v), want %s(%v)", match[1], got, returnType, want)
	}
}

// Suffix-like valid names cannot defeat repeated collision allocation. This
// bounded property probes 0..32 occupied suffixes for each generated base, with
// a byte-sequence field and its companions in the same complete namespace.
func TestOrdinaryIdentifierSourceSuffixProperty(t *testing.T) {
	for _, base := range []string{"p1", "p2", "requestData", "requestOffset", "requestLength", "output", "outputOffset", "outputCapacity", "result", "produced", "payloadOffset", "payloadLength"} {
		for count := 0; count <= 32; count++ {
			t.Run(fmt.Sprintf("%s/%d", base, count), func(t *testing.T) {
				fields := []Field{{Name: "payload", Type: FieldTypeBytesFixed, FixedLength: 2}, {Name: base, Type: FieldTypeU8}}
				for n := 1; n <= count; n++ {
					fields = append(fields, Field{Name: fmt.Sprintf("%s_%d", base, n), Type: FieldTypeU8})
				}
				tc := ordinaryIdentifierCase{"property", fields, []Field{{Name: "answer", Type: FieldTypeU8}, {Name: "tail", Type: FieldTypeBytes}}}
				_, src := identifierFiles(t, tc)
				assertIdentifierScopes(t, src)
			})
		}
	}
}

// Retains the original reviewer test name and six exact witnesses. Real javac
// accepts valid schemas, then dispatchTo must decode each positional argument
// and write only the supplied span. This is JVM behavior, not card qualification.
func TestReviewerOrdinaryIdentifierRegression(t *testing.T) {
	jar := simulatorJar(t)
	kit := os.Getenv("JCRPC_JCKIT_DIR")
	if kit == "" {
		t.Fatal("JCRPC_JCKIT_DIR is required for the identifier compilation gate")
	}
	if _, err := os.Stat(filepath.Join(kit, "lib/api_classic.jar")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range ordinaryIdentifierCases() {
		t.Run(tc.name, func(t *testing.T) {
			files, _ := identifierFiles(t, tc)
			root := t.TempDir()
			var javaFiles []string
			for _, f := range files {
				if strings.HasSuffix(f.Name, ".java") {
					p := filepath.Join(root, f.Name)
					writeTestFile(t, p, f.Data)
					javaFiles = append(javaFiles, p)
				}
			}
			harness := filepath.Join(root, "io/probe/IdentifierHarness.java")
			writeTestFile(t, harness, []byte(identifierHarness(tc)))
			args := append([]string{"-cp", filepath.Join(kit, "lib/api_classic.jar"), "-d", root}, javaFiles...)
			out, err := exec.Command("javac", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("valid IDL generated uncompilable ordinary handler: %v\n%s", err, out)
			}
			classpath := root + string(os.PathListSeparator) + jar
			out, err = exec.Command("javac", "-cp", classpath, "-d", root, harness).CombinedOutput()
			if err != nil {
				t.Fatalf("identifier runtime fixture compile: %v\n%s", err, out)
			}
			out, err = exec.Command("java", "-cp", classpath, "io.probe.IdentifierHarness").CombinedOutput()
			if err != nil {
				t.Fatalf("identifier dispatch witness: %v\n%s", err, out)
			}
		})
	}
}

// Independent fixture oracle: request bytes and override types/order come from
// IDL fields, not the allocator or generated method declarations. It checks
// multiple borrowed spans, P1/P2, all scalar returns, writer capacity and void.
func identifierHarness(tc ordinaryIdentifierCase) string {
	var params, checks, input []string
	p1, p2 := 0, 0
	for i, f := range tc.request {
		arg := fmt.Sprintf("arg%d", i)
		value := 17 + i
		typ := "byte"
		if f.Type == FieldTypeBool {
			typ, value = "boolean", 1
		} else if f.Type == FieldTypeU16 {
			typ, value = "short", 0x1234
		} else if f.Type == FieldTypeU32 {
			typ, value = "int", 0x12345678
		}
		if f.Type == FieldTypeBytes || f.Type == FieldTypeBytesFixed {
			params = append(params, "byte[] "+arg, "short "+arg+"Offset", "short "+arg+"Length")
			length := 2
			if f.Type == FieldTypeBytesFixed {
				length = f.FixedLength
			}
			checks = append(checks, fmt.Sprintf("check(%sOffset == %d && %sLength == %d, \"borrowed span window\");", arg, 5+len(input), arg, length))
			for j := 0; j < length; j++ {
				v := 49 + i + j
				input = append(input, fmt.Sprintf("(byte)%d", v))
				checks = append(checks, fmt.Sprintf("check(%s[(short)(%sOffset + %d)] == (byte)%d, \"borrowed span value\");", arg, arg, j, v))
			}
			continue
		}
		params = append(params, typ+" "+arg)
		want := fmt.Sprintf("(%s)%d", typ, value)
		if typ == "boolean" {
			want = "true"
		}
		checks = append(checks, fmt.Sprintf("check(%s == %s, \"scalar argument %d\");", arg, want, i))
		switch f.Location {
		case ParameterLocationP1:
			p1 = value
		case ParameterLocationP2:
			p2 = value
		default:
			width := 1
			if f.Type == FieldTypeU16 {
				width = 2
			} else if f.Type == FieldTypeU32 {
				width = 4
			}
			for j := width - 1; j >= 0; j-- {
				input = append(input, fmt.Sprintf("(byte)%d", (value>>(j*8))&255))
			}
		}
	}
	returnType, width, body := "void", 0, ""
	if len(tc.response) == 1 {
		switch tc.response[0].Type {
		case FieldTypeU8:
			returnType, width, body = "byte", 1, "return (byte)0x63;"
		case FieldTypeBool:
			returnType, width, body = "boolean", 1, "return true;"
		case FieldTypeU16:
			returnType, width, body = "short", 2, "return (short)0x6374;"
		case FieldTypeU32:
			returnType, width, body = "int", 4, "return 0x63748596;"
		}
	}
	if len(tc.response) > 0 && body == "" {
		returnType, width = "short", 0
		capacity := 126
		for _, f := range tc.response {
			switch f.Type {
			case FieldTypeU8:
				width++
			case FieldTypeU16:
				width += 2
			case FieldTypeBytesFixed:
				width += f.FixedLength
			case FieldTypeBytes:
				width += 3
			}
		}
		if tc.response[len(tc.response)-1].Type != FieldTypeBytes {
			capacity = width
		}
		params = append(params, "byte[] destination", "short start", "short capacity")
		checks = append(checks, fmt.Sprintf("check(start == 7 && capacity == %d, \"writer window\");", capacity))
		body = fmt.Sprintf("for (short i=0; i<%d; i++) destination[(short)(start+i)] = (byte)(0x63+17*i); return (short)%d;", width, width)
	}
	return fmt.Sprintf(`package io.probe;
public final class IdentifierHarness extends ProbeSkeleton {
    private short calls;
    private IdentifierHarness() { super(null); }
    private static void check(boolean ok, String claim) { if (!ok) throw new AssertionError(claim); }
    protected %s onEcho(%s) { %s calls++; %s }
    public static void main(String[] args) {
        new com.licel.jcardsim.base.Simulator();
        IdentifierHarness logic = new IdentifierHarness();
        byte[] wire = new byte[]{%s};
        byte[] input = new byte[133];
        for (short i=0; i<wire.length; i++) input[(short)(5+i)] = wire[i];
        byte[] output = new byte[133];
        for (short i=0; i<output.length; i++) output[i] = (byte)0x5A;
        short produced = logic.dispatchTo((byte)1, (byte)%d, (byte)%d, input, (short)5, (short)wire.length, output, (short)7, (short)126);
        check(produced == %d && logic.calls == 1, "produced/callback count");
        for (short i=0; i<output.length; i++) {
            byte expected = (byte)0x5A;
            if (i>=7 && i<7+produced) expected = (byte)(0x63+17*(i-7));
            %s
            check(output[i] == expected, "output wire/neighbors");
        }
    }
}
`, returnType, strings.Join(params, ", "), strings.Join(checks, "\n"), body, strings.Join(input, ", "), p1, p2, width, func() string {
		if len(tc.response) == 1 && tc.response[0].Type == FieldTypeBool {
			return "if (i==7) expected = (byte)1;"
		}
		return ""
	}())
}
