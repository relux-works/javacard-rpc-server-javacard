package codegen

import (
	"fmt"
	"strings"
	"testing"
)

// A successful READ_CLOSE must erase persistent result bytes even when the
// first result byte is 9. The neighboring 3-prefix lifecycle control is retained
// under TestGeneratedPersistentWorkspaceLifecycle; both storage/lifecycle modes
// drive Applet.process -> closeRead with valid digests and inspect the workspace.
func TestGeneratedReadCloseWipesNinePrefix(t *testing.T) {
	for _, policy := range []string{"transient", "persistent"} {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			t.Run(policy+"/"+string(memory), func(t *testing.T) {
				r, e := GenerateJavaSkeletonWithOptions(workspaceSchema(t, policy), "io.jcrpc.streamdemo.server", JavaOptions{StreamMemory: memory})
				if e != nil {
					t.Fatal(e)
				}
				harness := strings.ReplaceAll(workspaceLifecycleHarness, "PERSISTENT", fmt.Sprint(policy == "persistent"))
				harness = strings.Replace(harness, "byte[] fresh={1,2,3};", "byte[] fresh={1,2,9};", 1)
				harness = strings.Replace(harness, "byte[] expected={3,2,1};", "byte[] expected={9,2,1};", 1)
				output, e := runWorkspaceJava(t, r, harness, trackedJCSystem)
				if e != nil {
					t.Fatalf("READ_CLOSE prefix-nine: %v\n%s", e, output)
				}
			})
		}
	}
}
