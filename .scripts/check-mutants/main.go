// check-mutants runs bounded gate widenings in disposable task-local fixtures.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mutation struct{ name, path, from, to, test string }
type receipt struct {
	Mutant, Test, Claim, Bound string
	Exit                       int
}

func main() {
	out := flag.String("out", ".temp/mutants", "receipt directory")
	only := flag.String("only", "", "one mutant, or empty for all")
	flag.Parse()
	if e := run(*out, *only); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out, only string) error {
	out, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
	mutations := []mutation{
		{"status-one-ins", "codegen/internal/render/gen_java.go", "sharedFailure.setStatusWord(statusWord);", "if (statusWord == SW_INS_NOT_SUPPORTED) return new StatusWordException(statusWord);\n        sharedFailure.setStatusWord(statusWord);", "TestGeneratedJavaSkeletonUnknownInsReusesOneException"},
		{"wipe-prefix-nine", "codegen/internal/render/gen_java_stream.go", "wipe(workspace);", "if (workspace[0] != (byte)9) wipe(workspace);", "TestGeneratedReadCloseWipesNinePrefix"},
		{"workspace-ram", "codegen/internal/render/gen_java.go", `s.Applet.StreamWorkspace != "persistent" {`, `s.Applet.StreamWorkspace != "persistent" && s.Applet.StreamWorkspace != "ram" {`, "TestStreamWorkspacePolicy"},
		{"memory-select", "codegen/internal/render/gen_java.go", `case "", StreamMemoryClearOnDeselect:`, `case "", "clear_on_select", StreamMemoryClearOnDeselect:`, "TestPluginRefusalsHaveNoEffects/unknown-memory"},
		{"namespace-tab", "codegen/internal/render/gen_java.go", `if strings.TrimSpace(packageName) == "" {`, `if strings.TrimSpace(packageName) == "" && packageName != " \\t" {`, "TestPluginRefusalsHaveNoEffects/empty-namespace"},
		{"package-byte-counter", "codegen/plugin.go", `for _, f := range []pluginapi.File{`, `if s.Applet.Name == "Counter" && o.Namespace == "io.parity.server" { files[0].Data[0] ^= 1 }; for _, f := range []pluginapi.File{`, "TestPluginReleasedV045Parity"},
		{"runtime-cla-B1", "src/main/java/io/jcrpc/server/AppletBase.java", `if (buf[ISO7816.OFFSET_CLA] != cla) {`, `if (buf[ISO7816.OFFSET_CLA] != cla && buf[ISO7816.OFFSET_CLA] != (byte)0xB1) {`, "TestRootAppletBaseRealSimulator"},
		{"dependency-toml", "codegen/plugin.go", `"fmt"`, `"fmt"; _ "github.com/BurntSushi/toml"`, "TestPluginPublishedDependencyBoundary"},
	}
	receipts := []receipt{}
	for _, m := range mutations {
		if only != "" && only != m.name {
			continue
		}
		root := filepath.Join(out, m.name)
		if _, e = os.Stat(root); !os.IsNotExist(e) {
			return fmt.Errorf("fixture already exists: %s", root)
		}
		if e = copyCandidate(root); e != nil {
			return e
		}
		p := filepath.Join(root, m.path)
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if strings.Count(string(b), m.from) != 1 && m.name != "wipe-prefix-nine" {
			return fmt.Errorf("%s anchor count", m.name)
		}
		replacement := m.to
		if m.name == "namespace-tab" {
			replacement = strings.ReplaceAll(replacement, `\\t`, `\t`)
		}
		if e = os.WriteFile(p, []byte(strings.Replace(string(b), m.from, replacement, 1)), 0644); e != nil {
			return e
		}
		if m.name == "dependency-toml" {
			p = filepath.Join(root, "go.mod")
			f, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
			if e != nil {
				return e
			}
			_, e = f.WriteString("\nrequire github.com/BurntSushi/toml v1.5.0\n")
			if closeErr := f.Close(); e == nil {
				e = closeErr
			}
			if e != nil {
				return e
			}
		}
		c := exec.Command("go", "test", "-mod=mod", "./codegen", "-run", "^"+m.test+"$", "-count=1", "-v")
		c.Dir = root
		c.Env = append(os.Environ(), "GOWORK=off")
		log, e := os.Create(filepath.Join(out, m.name+".log"))
		if e != nil {
			return e
		}
		c.Stdout = log
		c.Stderr = log
		err := c.Run()
		if e = log.Close(); e != nil {
			return e
		}
		exit := 0
		if err != nil {
			if x, ok := err.(*exec.ExitError); ok {
				exit = x.ExitCode()
			} else {
				return err
			}
		}
		b, e = os.ReadFile(filepath.Join(out, m.name+".log"))
		if e != nil {
			return e
		}
		expected := map[string]string{
			"status-one-ins":       "allocated a different exception",
			"wipe-prefix-nine":     "workspace wipe: residual bytes",
			"workspace-ram":        "invalid \"ram\": <nil>",
			"memory-select":        "refusal: file count=7 error=<nil>",
			"namespace-tab":        "refusal: file count=7 error=<nil>",
			"package-byte-counter": "release byte/order drift at file 0: settings.gradle",
			"runtime-cla-B1":       "AssertionError: response length",
			"dependency-toml":      "forbidden dependency:",
		}[m.name]
		killed := exit == 1 && expected != "" && strings.Contains(string(b), expected) && strings.Contains(string(b), "--- FAIL: "+strings.Split(m.test, "/")[0]) && !strings.Contains(string(b), "[build failed]") && !strings.Contains(string(b), "--- SKIP:")
		bound := "killed at named behavioral assertion"
		if !killed {
			bound = "SURVIVOR: no named failing test; this property is unproven"
		}
		receipts = append(receipts, receipt{m.name, m.test, m.from, bound, exit})
		fmt.Printf("%s exit=%d %s\n", m.name, exit, bound)
	}
	b, e := json.MarshalIndent(receipts, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "receipts.json"), append(b, '\n'), 0644); e != nil {
		return e
	}
	if len(receipts) == 0 {
		return fmt.Errorf("no mutants selected")
	}
	for _, r := range receipts {
		if strings.HasPrefix(r.Bound, "SURVIVOR") {
			return fmt.Errorf("surviving mutant %s", r.Mutant)
		}
	}
	return nil
}
func copyCandidate(root string) error {
	for _, name := range []string{"go.mod", "go.sum", "Makefile", "codegen", "src"} {
		info, e := os.Stat(name)
		if e != nil {
			return e
		}
		if !info.IsDir() {
			b, e := os.ReadFile(name)
			if e != nil {
				return e
			}
			if e = os.MkdirAll(root, 0755); e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(root, name), b, info.Mode().Perm()); e != nil {
				return e
			}
			continue
		}
		if e = filepath.WalkDir(name, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			dst := filepath.Join(root, p)
			if d.IsDir() {
				return os.MkdirAll(dst, 0755)
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("nonregular candidate %s", p)
			}
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			return os.WriteFile(dst, b, 0644)
		}); e != nil {
			return e
		}
	}
	return nil
}
