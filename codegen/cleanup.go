package codegen

import "github.com/relux-works/javacard-rpc-server-javacard/codegen/internal/render"

// StreamWorkspaceCleanupAuthenticatedInvalidate is the Applet.StreamWorkspaceCleanup
// selector for the authenticated persistent workspace with transient-only refusal
// invalidation. It requires Applet.StreamWorkspace == "persistent" and refuses
// methods with a response stream. The generated dispatch takes an explicit
// per-APDU authenticated flag; an unauthenticated stream APDU is refused with
// 6982 before any session or persistent effect.
const StreamWorkspaceCleanupAuthenticatedInvalidate = render.StreamWorkspaceCleanupAuthenticatedInvalidate
