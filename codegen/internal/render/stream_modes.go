package render

import (
	"fmt"
	"strings"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

// Per-method stream modes compose with the authenticated-invalidate runtime.
// A method without a mode keeps the authenticated contract of that runtime.
const (
	// StreamModePublicInvalidate admits unauthenticated APDUs for the method.
	// Accepted request chunks are staged in the persistent workspace; every
	// refused APDU writes no persistent byte and invalidates the session. A
	// streamed result is never stored: the handler prepares it at CLOSE_WRITE
	// and produces each chunk into the admitted RAM response span on demand.
	StreamModePublicInvalidate = pluginapi.StreamModePublicInvalidate
	// StreamModeChunked delivers each accepted request chunk to the handler as
	// it arrives, from the caller's request span. Nothing is staged, the request
	// digest is computed incrementally, and no APDU of the method, accepted or
	// refused, writes persistent memory. A short result is written into the
	// admitted RAM response span; a streamed result is produced into it on each
	// read, like the public producer, from handler-held state only.
	StreamModeChunked = pluginapi.StreamModeChunked
)

// Generated Java values of a method's stream mode, one byte per streamed method.
const (
	javaStreamModeAuthenticated byte = 0
	javaStreamModePublic        byte = 1
	javaStreamModeChunked       byte = 2
)

func javaStreamModeValue(mode string) byte {
	switch mode {
	case StreamModePublicInvalidate:
		return javaStreamModePublic
	case StreamModeChunked:
		return javaStreamModeChunked
	default:
		return javaStreamModeAuthenticated
	}
}

// validateStreamModes checks every per-method stream mode before any output is
// rendered. A mode is meaningful only inside the authenticated-invalidate
// runtime and only for a method with a request stream: an unknown or misplaced
// mode is refused, never ignored.
func validateStreamModes(s *Schema, methods []javaMethodRender) error {
	var errs []string
	for _, method := range methods {
		if method.StreamMode == "" {
			continue
		}
		where := fmt.Sprintf("%s (INS 0x%02X)", method.Name, method.INS)
		switch method.StreamMode {
		case StreamModePublicInvalidate, StreamModeChunked:
		default:
			errs = append(errs, fmt.Sprintf("%s: unknown stream mode %q", where, method.StreamMode))
			continue
		}
		if !method.IsStream {
			errs = append(errs, fmt.Sprintf("%s: stream mode %q applies only to a streamed method", where, method.StreamMode))
			continue
		}
		if s.Applet.StreamWorkspaceCleanup != StreamWorkspaceCleanupAuthenticatedInvalidate {
			errs = append(errs, fmt.Sprintf("%s: stream mode %q requires stream_workspace_cleanup %q", where, method.StreamMode, StreamWorkspaceCleanupAuthenticatedInvalidate))
			continue
		}
		if method.RequestStream == nil {
			errs = append(errs, fmt.Sprintf("%s: stream mode %q requires a request stream", where, method.StreamMode))
			continue
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid stream modes: %s", strings.Join(errs, "; "))
	}
	return nil
}

func hasJavaStreamModes(methods []javaMethodRender) bool {
	for _, method := range methods {
		if method.IsStream && method.StreamMode != "" {
			return true
		}
	}
	return false
}

// streamMethodsInOrder returns the streamed methods with their generated
// method ids, which follow INS order and start at 1.
func streamMethodsInOrder(methods []javaMethodRender) []javaMethodRender {
	streamed := make([]javaMethodRender, 0, len(methods))
	for _, method := range methods {
		if method.IsStream {
			streamed = append(streamed, method)
		}
	}
	return streamed
}

// mixedJavaStreamDispatchSupport adds the per-method mode table to the
// authenticated dispatch support and passes the row's mode to the runtime.
func mixedJavaStreamDispatchSupport(source string, methods []javaMethodRender) string {
	streamed := streamMethodsInOrder(methods)
	var table strings.Builder
	table.WriteString(`    // Stream mode per row, the runtime's MODE_* value: 0 authenticated,
    // 1 public-invalidate, 2 chunked.
    private static final byte[] STREAM_MODES = {
`)
	writeJavaByteRows(&table, len(streamed), func(i int) string {
		return fmt.Sprintf("(byte) %d", javaStreamModeValue(streamed[i].StreamMode))
	})
	table.WriteString("\n")
	return strings.NewReplacer(
		"    private static final short STREAM_LIMIT_COLUMNS = (short) 5;\n",
		table.String()+"    private static final short STREAM_LIMIT_COLUMNS = (short) 5;\n",
		"            return streamSession.dispatch((byte) (row + (short) 1), operation,\n",
		"            return streamSession.dispatch((byte) (row + (short) 1), operation, STREAM_MODES[row],\n",
	).Replace(source)
}

// javaStreamMixedWorkspaceLength sizes the persistent workspace for the staged
// methods only: a chunked method stages nothing and a public streamed result is
// produced into RAM, so neither contributes beyond its staged request.
func javaStreamMixedWorkspaceLength(methods []javaMethodRender) int {
	result := 0
	for _, method := range streamMethodsInOrder(methods) {
		if method.StreamMode == StreamModeChunked {
			continue
		}
		if method.RequestStream != nil && method.RequestStream.MaxLength > result {
			result = method.RequestStream.MaxLength
		}
		if method.ResponseStream == nil && result < 255 {
			result = 255
		}
	}
	if result == 0 {
		return 255
	}
	return result
}

// buildJavaStreamMixedAbstractSupport implements the endpoint's Handler and
// Sha256 for the per-method modes and declares one typed callback set per
// method: staged short result, chunked delivery, or streamed-result producer.
func buildJavaStreamMixedAbstractSupport(methods []javaMethodRender) string {
	streamed := streamMethodsInOrder(methods)
	cases := func(b *strings.Builder, admit func(javaMethodRender) bool, call func(string) string) {
		for i, method := range streamed {
			if admit(method) {
				fmt.Fprintf(b, "            case %d:\n%s", i+1, call(toPascal(method.Name)))
			}
		}
	}
	staged := func(m javaMethodRender) bool { return m.StreamMode != StreamModeChunked && m.ResponseStream == nil }
	chunked := func(m javaMethodRender) bool { return m.StreamMode == StreamModeChunked }
	chunkedShort := func(m javaMethodRender) bool { return chunked(m) && m.ResponseStream == nil }
	chunkedProducer := func(m javaMethodRender) bool { return chunked(m) && m.ResponseStream != nil }
	producer := func(m javaMethodRender) bool {
		return m.StreamMode == StreamModePublicInvalidate && m.ResponseStream != nil
	}
	const workspace = "callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity"
	const defaultCase = `            default:
                failStream(SW_INS_NOT_SUPPORTED);
                return (short) 0;
        }
    }
`
	var b strings.Builder
	b.WriteString(`    @Override
    public final void digest(
            byte[] input,
            short inputOffset,
            short inputLength,
            byte[] output,
            short outputOffset) {
        streamSha256.doFinal(input, inputOffset, inputLength, output, outputOffset);
    }

    @Override
    public final void resetDigest() {
        streamSha256.reset();
    }

    @Override
    public final void updateDigest(
            byte[] input,
            short inputOffset,
            short inputLength) {
        streamSha256.update(input, inputOffset, inputLength);
    }

    @Override
    public final short execute(
            byte methodId,
            byte[] input,
            short inputOffset,
            short inputLength,
            byte[] output,
            short outputOffset,
            short outputCapacity,
            byte[] callerWorkspace,
            short callerWorkspaceOffset,
            short callerWorkspaceCapacity) {
        switch (methodId) {
`)
	cases(&b, staged, func(name string) string {
		return fmt.Sprintf("                return on%sStream(input, inputOffset, inputLength,\n                        output, outputOffset, outputCapacity, %s);\n", name, workspace)
	})
	b.WriteString(defaultCase)
	b.WriteString(`
    @Override
    public final void acceptChunk(
            byte methodId,
            short packetIndex,
            short packetCount,
            byte[] chunk,
            short chunkOffset,
            short chunkLength,
            byte[] callerWorkspace,
            short callerWorkspaceOffset,
            short callerWorkspaceCapacity) {
        switch (methodId) {
`)
	cases(&b, chunked, func(name string) string {
		return fmt.Sprintf("                on%sChunk(packetIndex, packetCount, chunk, chunkOffset, chunkLength,\n                        %s);\n                return;\n", name, workspace)
	})
	b.WriteString(`            default:
                failStream(SW_INS_NOT_SUPPORTED);
        }
    }

    @Override
    public final short finishChunks(
            byte methodId,
            short inputLength,
            byte[] output,
            short outputOffset,
            short outputCapacity,
            byte[] callerWorkspace,
            short callerWorkspaceOffset,
            short callerWorkspaceCapacity) {
        switch (methodId) {
`)
	cases(&b, chunkedShort, func(name string) string {
		return fmt.Sprintf("                return on%sFinish(inputLength, output, outputOffset, outputCapacity,\n                        %s);\n", name, workspace)
	})
	b.WriteString(defaultCase)
	b.WriteString(`
    @Override
    public final short prepareResult(
            byte methodId,
            byte[] input,
            short inputOffset,
            short inputLength,
            byte[] callerWorkspace,
            short callerWorkspaceOffset,
            short callerWorkspaceCapacity) {
        switch (methodId) {
`)
	cases(&b, func(m javaMethodRender) bool { return producer(m) || chunkedProducer(m) }, func(name string) string {
		for _, m := range streamed {
			if toPascal(m.Name) == name && chunkedProducer(m) {
				return fmt.Sprintf("                return on%sPrepare(inputLength, %s);\n", name, workspace)
			}
		}
		return fmt.Sprintf("                return on%sPrepare(input, inputOffset, inputLength, %s);\n", name, workspace)
	})
	b.WriteString(defaultCase)
	b.WriteString(`
    @Override
    public final void produceResult(
            byte methodId,
            byte[] input,
            short inputOffset,
            short inputLength,
            short resultOffset,
            byte[] output,
            short outputOffset,
            short length,
            byte[] callerWorkspace,
            short callerWorkspaceOffset,
            short callerWorkspaceCapacity) {
        switch (methodId) {
`)
	cases(&b, func(m javaMethodRender) bool { return producer(m) || chunkedProducer(m) }, func(name string) string {
		for _, m := range streamed {
			if toPascal(m.Name) == name && chunkedProducer(m) {
				return fmt.Sprintf("                on%sProduce(resultOffset, output, outputOffset, length,\n                        %s);\n                return;\n", name, workspace)
			}
		}
		return fmt.Sprintf("                on%sProduce(input, inputOffset, inputLength, resultOffset,\n                        output, outputOffset, length, %s);\n                return;\n", name, workspace)
	})
	b.WriteString(`            default:
                failStream(SW_INS_NOT_SUPPORTED);
        }
    }

    /** Generated no-allocation failure path for typed stream handlers. */
    protected final void failStream(short statusWord) {
        streamHandlerFailure.setStatusWord(statusWord);
        throw streamHandlerFailure;
    }

`)
	for _, method := range streamed {
		name := toPascal(method.Name)
		switch {
		case chunked(method):
			fmt.Fprintf(&b, "    /** %s, chunked: consume one accepted request chunk, in order; nothing is staged. */\n", method.Signature)
			fmt.Fprintf(&b, "    protected abstract void on%sChunk(\n", name)
			b.WriteString("            short packetIndex, short packetCount,\n")
			b.WriteString("            byte[] chunk, short chunkOffset, short chunkLength,\n")
			b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
			if chunkedProducer(method) {
				fmt.Fprintf(&b, "    /** %s, chunked streamed result: every chunk arrived and the digest matched; prepare the result from handler state and return its total length. */\n", method.Signature)
				fmt.Fprintf(&b, "    protected abstract short on%sPrepare(\n", name)
				b.WriteString("            short inputLength,\n")
				b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
				fmt.Fprintf(&b, "    /** %s, chunked streamed result: write the same bytes [resultOffset, resultOffset + length) every time. */\n", method.Signature)
				fmt.Fprintf(&b, "    protected abstract void on%sProduce(\n", name)
				b.WriteString("            short resultOffset,\n")
				b.WriteString("            byte[] output, short outputOffset, short length,\n")
				b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
				continue
			}
			fmt.Fprintf(&b, "    /** %s, chunked: every chunk arrived and the digest matched; return response length. */\n", method.Signature)
			fmt.Fprintf(&b, "    protected abstract short on%sFinish(\n", name)
			b.WriteString("            short inputLength,\n")
			b.WriteString("            byte[] output, short outputOffset, short outputCapacity,\n")
			b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
		case producer(method):
			fmt.Fprintf(&b, "    /** %s, public streamed result: prepare it and return its total length. */\n", method.Signature)
			fmt.Fprintf(&b, "    protected abstract short on%sPrepare(\n", name)
			b.WriteString("            byte[] input, short inputOffset, short inputLength,\n")
			b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
			fmt.Fprintf(&b, "    /** %s, public streamed result: write the same bytes [resultOffset, resultOffset + length) every time. */\n", method.Signature)
			fmt.Fprintf(&b, "    protected abstract void on%sProduce(\n", name)
			b.WriteString("            byte[] input, short inputOffset, short inputLength, short resultOffset,\n")
			b.WriteString("            byte[] output, short outputOffset, short length,\n")
			b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
		default:
			fmt.Fprintf(&b, "    /** %s; return response length and use failStream for a status word. */\n", method.Signature)
			fmt.Fprintf(&b, "    protected abstract short on%sStream(\n", name)
			b.WriteString("            byte[] input, short inputOffset, short inputLength,\n")
			b.WriteString("            byte[] output, short outputOffset, short outputCapacity,\n")
			b.WriteString("            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity);\n\n")
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}
