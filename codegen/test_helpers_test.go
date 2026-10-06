package codegen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc-server-javacard/codegen/internal/render"
	"github.com/relux-works/javacard-rpc/pluginapi"
)

type Schema = pluginapi.Schema
type Applet = pluginapi.Applet
type Method = pluginapi.Method
type Message = pluginapi.Message
type Field = pluginapi.Field
type StatusWord = pluginapi.StatusWord
type FieldType = pluginapi.FieldType
type ParameterLocation = pluginapi.ParameterLocation
type StreamMemory = render.StreamMemory
type JavaOptions = render.JavaOptions
type JavaGenerationResult = render.JavaGenerationResult

const (
	FieldTypeU8                 = pluginapi.FieldTypeU8
	FieldTypeU16                = pluginapi.FieldTypeU16
	FieldTypeU32                = pluginapi.FieldTypeU32
	FieldTypeBool               = pluginapi.FieldTypeBool
	FieldTypeASCII              = pluginapi.FieldTypeASCII
	FieldTypeString             = pluginapi.FieldTypeString
	FieldTypeBytes              = pluginapi.FieldTypeBytes
	FieldTypeBytesFixed         = pluginapi.FieldTypeBytesFixed
	FieldTypeStream             = pluginapi.FieldTypeStream
	ParameterLocationNone       = pluginapi.ParameterLocationNone
	ParameterLocationP1         = pluginapi.ParameterLocationP1
	ParameterLocationP2         = pluginapi.ParameterLocationP2
	ParameterLocationData       = pluginapi.ParameterLocationData
	StreamMemoryClearOnDeselect = render.StreamMemoryClearOnDeselect
	StreamMemoryClearOnReset    = render.StreamMemoryClearOnReset
)

// ParseFile is a test-only fixture loader, not a TOML parser. These frozen JSON
// models were exported from the pinned donor's validated parity IDLs.
func ParseFile(name string) (*Schema, error) {
	name = strings.TrimSuffix(name, filepath.Ext(name)) + ".json"
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var s Schema
	err = json.Unmarshal(b, &s)
	return &s, err
}

// Retained regression names consume the actual plugin package; the view below
// only unpacks its ordered files for the original JVM/CAP harnesses.
func GenerateJavaSkeleton(s *Schema, namespace string) (*JavaGenerationResult, error) {
	return GenerateJavaSkeletonWithOptions(s, namespace, JavaOptions{})
}
func GenerateJavaSkeletonWithOptions(s *Schema, namespace string, options JavaOptions) (*JavaGenerationResult, error) {
	files, err := (Plugin{}).Generate(s, pluginapi.Options{Namespace: namespace, StreamMemory: string(options.StreamMemory), SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"})
	if err != nil {
		return nil, err
	}
	r := &JavaGenerationResult{}
	for _, f := range files {
		stem := strings.TrimSuffix(filepath.Base(f.Name), ".java")
		switch {
		case strings.HasSuffix(stem, "Transport"):
			r.TransportName = stem
			r.TransportSource = f.Data
		case strings.HasSuffix(stem, "Skeleton"):
			r.SkeletonName = stem
			r.SkeletonSource = f.Data
		case strings.HasSuffix(stem, "StreamEndpoint"):
			r.StreamEndpointName = stem
			r.StreamEndpointSource = f.Data
		case strings.HasSuffix(stem, "BoundedStreamRuntime"):
			r.StreamRuntimeName = stem
			r.StreamRuntimeSource = f.Data
		case strings.HasSuffix(stem, "StreamAPDUAdapter"):
			r.StreamAPDUAdapterName = stem
			r.StreamAPDUAdapterSource = f.Data
		}
	}
	return r, nil
}
func writeTestFile(t *testing.T, name string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(name), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(name, b, 0644); e != nil {
		t.Fatal(e)
	}
}
func intPtr(n int) *int { return &n }
