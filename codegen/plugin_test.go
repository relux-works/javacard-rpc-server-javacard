package codegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

type parityFile struct{ Name, SHA256 string }
type parityCase struct {
	Fixture, Policy string
	Options         pluginapi.Options
	Files           []parityFile
}
type parityMatrix struct {
	BaselineTag, BaselineCommit, BaselineBinarySHA256, DonorCommit string
	Cases                                                          []parityCase
}

// This independent release matrix pins the Java projection of every core IDL,
// workspace, lifecycle, simulator coordinate and namespace combination. Names,
// order, bytes and input immutability are checked at Plugin.Generate.
func TestPluginReleasedV045Parity(t *testing.T) {
	b, e := os.ReadFile("testdata/parity-v0.4.5.json")
	if e != nil {
		t.Fatal(e)
	}
	var matrix parityMatrix
	if e = json.Unmarshal(b, &matrix); e != nil {
		t.Fatal(e)
	}
	if matrix.BaselineTag != "v0.4.5" || len(matrix.Cases) != 216 {
		t.Fatalf("incomplete release matrix: %s %d", matrix.BaselineTag, len(matrix.Cases))
	}
	seen := map[string]bool{}
	for _, tc := range matrix.Cases {
		t.Run(tc.Fixture+"/"+tc.Policy+"/"+tc.Options.Namespace+"/"+tc.Options.StreamMemory+"/"+tc.Options.SimulatorDependency, func(t *testing.T) {
			s, e := ParseFile("testdata/" + tc.Fixture + ".json")
			if e != nil {
				t.Fatal(e)
			}
			s.Applet.StreamWorkspace = tc.Policy
			before, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			options := tc.Options
			if options.SimulatorDependency == "" {
				options.SimulatorDependency = "com.klinec:jcardsim:3.0.5.9"
			}
			files, e := (Plugin{}).Generate(s, options)
			if e != nil {
				t.Fatal(e)
			}
			key := tc.Fixture + "|" + tc.Policy + "|" + tc.Options.Namespace + "|" + tc.Options.StreamMemory + "|" + tc.Options.SimulatorDependency
			if seen[key] {
				t.Fatalf("duplicate matrix row %s", key)
			}
			seen[key] = true
			if len(files) != len(tc.Files) {
				t.Fatalf("file count: %d want %d", len(files), len(tc.Files))
			}
			for i, f := range files {
				sum := sha256.Sum256(f.Data)
				if f.Name != tc.Files[i].Name || hex.EncodeToString(sum[:]) != tc.Files[i].SHA256 {
					t.Fatalf("release byte/order drift at file %d: %s", i, f.Name)
				}
			}
			after, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("plugin mutated input")
			}
		})
	}
	// Counts alone cannot prove the cross product: independently require all rows.
	for _, fixture := range []string{"counter", "stream", "example-counter", "bsim-auth"} {
		s, e := ParseFile("testdata/" + fixture + ".json")
		if e != nil {
			t.Fatal(e)
		}
		for _, policy := range []string{"", "transient", "persistent"} {
			for _, namespace := range []string{"io.parity.server", strings.ToLower(s.Applet.Name)} {
				for _, memory := range []string{"", "clear_on_deselect", "clear_on_reset"} {
					for _, coordinate := range []string{"com.klinec:jcardsim:3.0.5.9", "works.relux:jcardsim:3.0.5.9-relux.1", ""} {
						key := fixture + "|" + policy + "|" + namespace + "|" + memory + "|" + coordinate
						if !seen[key] {
							t.Errorf("missing parity row %s", key)
						}
					}
				}
			}
		}
	}
}

// Rejection returns no partial package, and generation never writes cwd. Schema
// validation and simulator-coordinate syntax are explicitly the facade's job.
func TestPluginRefusalsHaveNoEffects(t *testing.T) {
	s, e := ParseFile("testdata/stream.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		s    *Schema
		o    pluginapi.Options
		want string
	}{
		{"nil-schema", nil, pluginapi.Options{Namespace: "probe.server"}, "schema is nil"},
		{"empty-namespace", s, pluginapi.Options{Namespace: " \t"}, "package name is empty"},
		{"unknown-memory", s, pluginapi.Options{Namespace: "probe.server", StreamMemory: "clear_on_select"}, "unknown stream memory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			files, e := (Plugin{}).Generate(tc.s, tc.o)
			if e == nil || !strings.Contains(e.Error(), tc.want) || files != nil {
				t.Fatalf("refusal: file count=%d error=%v", len(files), e)
			}
			entries, e := os.ReadDir(".")
			if e != nil || len(entries) != 0 {
				t.Fatalf("filesystem effect: %v %v", entries, e)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		t.Chdir(t.TempDir())
		files, e := (Plugin{}).Generate(s, pluginapi.Options{Namespace: "probe.server", SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"})
		if e != nil || len(files) != 7 {
			t.Fatalf("valid package: %d %v", len(files), e)
		}
		entries, e := os.ReadDir(".")
		if e != nil || len(entries) != 0 {
			t.Fatalf("filesystem effect: %v %v", entries, e)
		}
	})
}

// The compiled transitive graph permits only released pluginapi outside this
// module, never the facade/parser. Reading failures cannot look like absence.
func TestPluginPublishedDependencyBoundary(t *testing.T) {
	c := exec.Command("go", "list", "-deps", "-f", "{{if .Module}}{{.ImportPath}} {{.Module.Path}} {{.Module.Version}} {{if .Module.Replace}}REPLACED{{end}}{{end}}", ".")
	c.Env = append(os.Environ(), "GOWORK=off")
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("go list: %v\n%s", e, b)
	}
	api := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 {
			t.Fatalf("malformed graph %q", line)
		}
		if f[1] == "github.com/relux-works/javacard-rpc-server-javacard" {
			continue
		}
		if len(f) != 3 || f[0] != "github.com/relux-works/javacard-rpc/pluginapi" || f[1] != "github.com/relux-works/javacard-rpc/pluginapi" || f[2] != "v0.1.0" {
			t.Fatalf("forbidden dependency: %q", line)
		}
		api = true
	}
	if !api {
		t.Fatal("published API absent")
	}
}
