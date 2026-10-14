package render

import (
	"fmt"
	"strings"
)

// StreamWorkspaceCleanupAuthenticatedInvalidate selects the persistent stream
// workspace that only authenticated APDUs may reach. A refused, aborted,
// deselected or reset session is invalidated in transient memory only: the
// runtime never erases or otherwise writes the persistent workspace outside an
// accepted authenticated WRITE chunk or an accepted short-result receipt.
const StreamWorkspaceCleanupAuthenticatedInvalidate = "authenticated-invalidate"

// requireAuthenticatedInvalidateMethods refuses response streams of methods
// without a stream mode. A streamed response stored by the handler in the
// persistent workspace during CLOSE_WRITE would leave persistent writes on an
// APDU the runtime may still refuse. Short results are staged in the caller
// response span instead, and a public-invalidate or chunked streamed result is
// produced into the admitted RAM response span on each read, never stored.
func requireAuthenticatedInvalidateMethods(methods []javaMethodRender) error {
	var refused []string
	for _, method := range methods {
		if method.IsStream && method.ResponseStream != nil && method.StreamMode == "" {
			refused = append(refused, fmt.Sprintf("%s (INS 0x%02X)", method.Name, method.INS))
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("stream workspace cleanup %q supports short results only; response streams cannot keep refused APDUs free of persistent writes: %s",
			StreamWorkspaceCleanupAuthenticatedInvalidate, strings.Join(refused, ", "))
	}
	return nil
}
