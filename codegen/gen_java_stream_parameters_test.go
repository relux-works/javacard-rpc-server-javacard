package codegen

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Count Java Card parameter words, including the receiver. An int occupies two
// words; a reference (including int[]) occupies one. This is source evidence,
// not a substitute for conversion by the Classic converter.
func streamParameterWords(parameters string, receiver bool) (int, error) {
	words := 0
	if receiver {
		words++
	}
	if strings.TrimSpace(parameters) == "" {
		return words, nil
	}
	for _, parameter := range strings.Split(parameters, ",") {
		fields := strings.Fields(parameter)
		if len(fields) != 2 {
			return 0, fmt.Errorf("unsupported parameter %q", parameter)
		}
		if fields[0] == "int" {
			words += 2
		} else {
			words++
		}
	}
	return words, nil
}

func TestGenerateJavaStreamParameterWords(t *testing.T) {
	for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
		for _, policy := range []string{"transient", "persistent", "tracked", "authenticated", "mixed"} {
			t.Run(string(memory)+"/"+policy, func(t *testing.T) {
				s, err := ParseFile("testdata/stream.toml")
				if err != nil {
					t.Fatal(err)
				}
				s.Applet.StreamWorkspace = "transient"
				switch policy {
				case "persistent", "tracked":
					s.Applet.StreamWorkspace = "persistent"
					if policy == "tracked" {
						s.Applet.StreamWorkspaceCleanup = "whole-reply-area"
					}
				case "authenticated":
					s = batchStoreSchema()
				case "mixed":
					s = modeStoreSchema()
				}
				r, err := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.parameters", JavaOptions{StreamMemory: memory})
				if err != nil {
					t.Fatal(err)
				}
				want := 14
				if policy == "authenticated" || policy == "mixed" {
					want = 15
				}
				for name, source := range map[string][]byte{"endpoint": r.StreamEndpointSource, "runtime": r.StreamRuntimeSource} {
					matches := regexp.MustCompile(`\bshort dispatch\(([^)]*)\)`).FindAllSubmatch(source, -1)
					if len(matches) != 1 {
						t.Fatalf("%s dispatch declarations: %d", name, len(matches))
					}
					words, err := streamParameterWords(string(matches[0][1]), true)
					if err != nil || words != want || words > 15 {
						t.Fatalf("%s dispatch: %d words, want %d, error %v", name, words, want, err)
					}
					t.Logf("%s dispatch: %d parameter words including receiver", name, words)
					// Plant a real oversized declaration in this generated signature.
					// The same counter must reject it by its word count, not setup.
					planted, err := streamParameterWords(string(matches[0][1])+", int overflow", true)
					if err != nil || planted != want+2 || planted <= 15 {
						t.Fatalf("%s oversized declaration escaped: %d words, error %v", name, planted, err)
					}
				}
				for _, binding := range []struct {
					name, method string
					source       []byte
					want         int
				}{
					{"skeleton", "short dispatchStreamTo", r.SkeletonSource, want - 1},
					{"constructor", r.StreamRuntimeName, r.StreamRuntimeSource, 9 + func() int {
						if policy == "mixed" {
							return 1
						}
						return 0
					}()},
				} {
					matches := regexp.MustCompile(`\b`+binding.method+`\(([^)]*)\)`).FindAllSubmatch(binding.source, -1)
					if len(matches) != 1 {
						t.Fatalf("%s declarations: %d", binding.name, len(matches))
					}
					words, err := streamParameterWords(string(matches[0][1]), true)
					if err != nil || words != binding.want || words > 15 {
						t.Fatalf("%s: %d words, want %d, error %v", binding.name, words, binding.want, err)
					}
				}
			})
		}
	}
}

// Positive controls and oversized declarations establish that receiver/int
// widths are counted and the former flattened contract exceeds the limit.
func TestGenerateJavaStreamParameterWordControls(t *testing.T) {
	for _, tc := range []struct {
		parameters string
		receiver   bool
		want       int
	}{
		{"", true, 1},
		{"int value, int[] buffer, short offset", true, 5},
		{"int value, int[] buffer, short offset", false, 4},
		{strings.Repeat("short value,", 14) + "int wide", true, 17},
		{strings.Repeat("short value,", 21) + "Handler handler", true, 23},
	} {
		got, err := streamParameterWords(tc.parameters, tc.receiver)
		if err != nil || got != tc.want {
			t.Fatalf("%q: %d, want %d, error %v", tc.parameters, got, tc.want, err)
		}
	}
	if _, err := streamParameterWords("not a parameter", true); err == nil {
		t.Fatal("malformed parameter accepted")
	}
}
