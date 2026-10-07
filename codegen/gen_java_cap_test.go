package codegen

import (
	"archive/zip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredCAPTargetFailsWhenAntIsUnavailable(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is not available")
	}
	command := exec.Command(makePath, "-f", filepath.Join("..", "Makefile"), "test-cap")
	command.Env = append(os.Environ(),
		"PATH="+t.TempDir(),
		"JCRPC_ANT_JAVACARD_JAR=/configured/ant-javacard.jar",
		"JCRPC_JCKIT_DIR=/configured/jckit",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("required CAP target unexpectedly passed without ant:\n%s", output)
	}
	if !strings.Contains(string(output), "ant is required") {
		t.Fatalf("required CAP target failed for the wrong reason: %v\n%s", err, output)
	}
}

func TestGeneratedJavaStreamPackageConvertsToCAP(t *testing.T) {
	ant, err := exec.LookPath("ant")
	if err != nil {
		t.Skip("ant is not available")
	}
	antJavaCardJar := os.Getenv("JCRPC_ANT_JAVACARD_JAR")
	jckitDir := os.Getenv("JCRPC_JCKIT_DIR")
	if antJavaCardJar == "" || jckitDir == "" {
		t.Skip("set JCRPC_ANT_JAVACARD_JAR and JCRPC_JCKIT_DIR for CAP conversion smoke")
	}
	// Real converter verification includes both storage policies and both
	// lifecycle modes; simulator javac success alone does not establish this.
	for _, policy := range []string{"transient", "persistent"} {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			t.Run(policy+"/"+string(memory), func(t *testing.T) {
				convertStreamCAP(t, ant, antJavaCardJar, jckitDir, policy, memory)
			})
		}
	}
}

func convertStreamCAP(t *testing.T, ant, antJavaCardJar, jckitDir, policy string, memory StreamMemory) {
	convertCleanupCAP(t, ant, antJavaCardJar, jckitDir, policy, memory, "")
}

func convertCleanupCAP(t *testing.T, ant, antJavaCardJar, jckitDir, policy string, memory StreamMemory, cleanup string) int64 {
	t.Helper()

	schema, err := ParseFile(filepath.Join("testdata", "stream.toml"))
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	schema.Applet.StreamWorkspace = policy
	schema.Applet.StreamWorkspaceCleanup = cleanup
	result, err := GenerateJavaSkeletonWithOptions(schema, "io.jcrpc.streamdemo.server", JavaOptions{StreamMemory: memory})
	if err != nil {
		t.Fatalf("GenerateJavaSkeleton returned error: %v", err)
	}

	root := t.TempDir()
	sourceDir := filepath.Join(root, "src", "io", "jcrpc", "streamdemo", "server")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll source: %v", err)
	}
	files := map[string][]byte{
		result.TransportName + ".java":         result.TransportSource,
		result.SkeletonName + ".java":          result.SkeletonSource,
		result.StreamEndpointName + ".java":    result.StreamEndpointSource,
		result.StreamRuntimeName + ".java":     result.StreamRuntimeSource,
		result.StreamAPDUAdapterName + ".java": result.StreamAPDUAdapterSource,
		"StreamDemoApplet.java":                []byte(streamDemoAppletFixture),
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, name), source, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	buildXML := fmt.Sprintf(`<project name="generated-stream-cap" default="cap">
    <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/>
    <target name="cap">
        <javacard>
            <cap jckit="%s"
                 sources="%s"
                 package="io.jcrpc.streamdemo.server"
                 aid="F000000102"
                 version="1.0"
                 ints="true"
                 output="%s">
                <applet class="io.jcrpc.streamdemo.server.StreamDemoApplet" aid="F00000010201"/>
            </cap>
        </javacard>
    </target>
</project>
`, filepath.ToSlash(antJavaCardJar), filepath.ToSlash(jckitDir),
		filepath.ToSlash(filepath.Join(root, "src")), filepath.ToSlash(filepath.Join(root, "streamdemo.cap")))
	buildPath := filepath.Join(root, "build.xml")
	if err := os.WriteFile(buildPath, []byte(buildXML), 0o644); err != nil {
		t.Fatalf("write build.xml: %v", err)
	}

	command := exec.Command(ant, "-f", buildPath, "cap")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("CAP conversion failed: %v\n%s", err, output)
	}
	info, err := os.Stat(filepath.Join(root, "streamdemo.cap"))
	if err != nil || info.Size() == 0 {
		t.Fatalf("CAP output missing or empty: %v", err)
	}
	capZIP, err := zip.OpenReader(filepath.Join(root, "streamdemo.cap"))
	if err != nil {
		t.Fatal(err)
	}
	defer capZIP.Close()
	var componentBytes, codeBytes uint64
	for _, file := range capZIP.File {
		if strings.HasSuffix(file.Name, ".cap") {
			componentBytes += file.UncompressedSize64
			if strings.HasSuffix(file.Name, "/Method.cap") {
				codeBytes = file.UncompressedSize64
			}
		}
	}
	if componentBytes == 0 || codeBytes == 0 {
		t.Fatal("CAP component inventory missing")
	}
	t.Logf("CAP components=%d B; Method.cap=%d B; ZIP=%d B", componentBytes, codeBytes, info.Size())
	return info.Size()
}

// Default and whole reply must convert and verify with the real Classic SDK. This
// proves converter acceptance, not card installation or physical RAM capacity.
func TestPersistentCleanupCAP(t *testing.T) {
	ant, err := exec.LookPath("ant")
	if err != nil {
		t.Fatal(err)
	}
	jar, kit := os.Getenv("JCRPC_ANT_JAVACARD_JAR"), os.Getenv("JCRPC_JCKIT_DIR")
	if jar == "" || kit == "" {
		t.Skip("set CAP toolchain variables")
	}
	for _, cleanup := range append([]string{""}, cleanupModes...) {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			t.Run(cleanup+"/"+string(memory), func(t *testing.T) {
				size := convertCleanupCAP(t, ant, jar, kit, "persistent", memory, cleanup)
				t.Logf("verified CAP ZIP=%d B", size)
			})
		}
	}
}
