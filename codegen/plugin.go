package codegen

import (
	"fmt"
	"path"
	"strings"

	"github.com/relux-works/javacard-rpc-server-javacard/codegen/internal/packagefiles"
	"github.com/relux-works/javacard-rpc-server-javacard/codegen/internal/render"
	"github.com/relux-works/javacard-rpc/pluginapi"
)

// Plugin renders a complete Java Card package using the released plugin API.
type Plugin struct{}

var _ pluginapi.Plugin = Plugin{}

// Generate returns ordered package files without performing filesystem writes.
func (Plugin) Generate(s *pluginapi.Schema, o pluginapi.Options) ([]pluginapi.File, error) {
	r, err := render.GenerateJavaSkeletonWithOptions(s, o.Namespace,
		render.JavaOptions{StreamMemory: render.StreamMemory(o.StreamMemory)})
	if err != nil {
		return nil, err
	}
	stem := strings.ToLower(packagefiles.Stem(s.Applet.Name))
	files := []pluginapi.File{
		{Name: "settings.gradle", Data: []byte(fmt.Sprintf("rootProject.name = '%s-server-javacard'\n", stem))},
		{Name: "build.gradle", Data: []byte(GenerateBuildGradle(o.Namespace, s.Applet.Version, false, o.SimulatorDependency))},
		{Name: r.TransportName + ".java", Data: r.TransportSource},
		{Name: r.SkeletonName + ".java", Data: r.SkeletonSource},
	}
	for _, f := range []pluginapi.File{
		{Name: r.StreamEndpointName + ".java", Data: r.StreamEndpointSource},
		{Name: r.StreamRuntimeName + ".java", Data: r.StreamRuntimeSource},
		{Name: r.StreamAPDUAdapterName + ".java", Data: r.StreamAPDUAdapterSource},
	} {
		if len(f.Data) > 0 {
			files = append(files, f)
		}
	}
	for i := 2; i < len(files); i++ {
		files[i].Name = path.Join("src/main/java", strings.ReplaceAll(o.Namespace, ".", "/"), files[i].Name)
	}
	return files, nil
}
