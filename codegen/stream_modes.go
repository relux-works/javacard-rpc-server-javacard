package codegen

import "github.com/relux-works/javacard-rpc-server-javacard/codegen/internal/render"

// Per-method stream modes (Method.StreamMode). Both require the applet selector
// StreamWorkspaceCleanupAuthenticatedInvalidate with persistent workspace and a
// request stream; a method without a mode keeps the authenticated contract.
const (
	// StreamModePublicInvalidate admits unauthenticated APDUs, stages accepted
	// chunks in the persistent workspace, writes nothing persistent on any
	// refused APDU and produces a streamed result into RAM on each read.
	StreamModePublicInvalidate = render.StreamModePublicInvalidate
	// StreamModeChunked delivers request chunks to the handler as they arrive and
	// writes nothing persistent on any APDU; a streamed result is produced into
	// RAM on each read.
	StreamModeChunked = render.StreamModeChunked
)
