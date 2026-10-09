package render

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"unicode"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

const javaTransportTemplate = `package {{.PackageName}};

/**
 * Transport abstraction for {{.AppletName}} commands.
 * Implement this in your APDU adapter (or any other transport).
 */
public interface {{.TransportInterfaceName}} {
    byte[] transmit(byte ins, byte p1, byte p2, byte[] data);
}
`

const javaSkeletonTemplate = `package {{.PackageName}};

import javacard.framework.JCSystem;

/**
 * Generated skeleton for {{.AppletName}} applet.
 * DO NOT EDIT — this file is produced by javacard-rpc codegen from {{.SchemaFileName}}.
 *
 * CLA: 0x{{.CLAHex}}
 * Methods:
{{.MethodCommentBlock}} */
public abstract class {{.ClassName}} {

    // INS codes from {{.SchemaFileName}}
{{.INSConstantsBlock}}

    // Status words from {{.SchemaFileName}}
{{.StatusConstantsBlock}}

    public static final byte {{.CLAConstName}} = (byte) 0x{{.CLAHex}};

    private static final short SW_WRONG_LENGTH = (short) 0x6700;
    private static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;
    private final byte[] empty;
    // The one StatusWordException this instance ever constructs. Every
    // generated error path (dispatch default, pack*/read* guards,
    // fixed-length response checks) re-arms and rethrows it, so an
    // unauthenticated caller looping unknown or malformed frames cannot
    // grow the never-reclaimed Java Card heap (security audit S-01).
    private final StatusWordException sharedFailure;

    protected final {{.TransportInterfaceName}} transport;

    protected {{.ClassName}}({{.TransportInterfaceName}} transport) {
        this.transport = transport;
        this.empty = new byte[0];
        this.sharedFailure = new StatusWordException(SW_INS_NOT_SUPPORTED);
    }

    /**
     * Write a whole ordinary reply into caller-owned storage; return its length.
     * Null request storage is allowed only for the empty (0, 0) span.
     * No APDU reference is retained. Typed inputs are decoded before any write.
     * Byte-sequence inputs borrow request storage: consume overlapping input
     * before writing output. Handlers must respect capacity and never retain
     * request/output references. A rejected call yields no sendable length;
     * output may already contain handler writes and is not rolled back.
     */
    public final short dispatchTo(byte ins, byte p1, byte p2,
            byte[] requestBuffer, short requestOffset, short requestLength,
            byte[] output, short outputOffset, short outputCapacity) {
        if (requestBuffer == null && (requestOffset != 0 || requestLength != 0)) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        byte[] requestData = safeBytes(requestBuffer);
        checkWindow(requestData, requestOffset, requestLength);
        checkWindow(output, outputOffset, outputCapacity);
        switch (ins) {
{{.DispatchCasesBlock}}            default:
                throw statusWordFailure(SW_INS_NOT_SUPPORTED);
        }
    }

    protected final byte[] transmit(byte ins, byte p1, byte p2, byte[] data) {
        return safeBytes(transport.transmit(ins, p1, p2, safeBytes(data)));
    }

    // --- Dispatch wiring (reads request fields, calls abstract method, returns encoded response) ---

{{.HandlersBlock}}    // --- Abstract methods — developer implements these ---

{{.AbstractMethodsBlock}}
    // No-message, numeric-only exception: java.lang.String is not safely
    // convertible on real Java Card Classic runtimes (no StringBuilder,
    // restricted String API), so this deliberately carries no message --
    // callers should read getStatusWord() instead of getMessage().
    // The reusable exception keeps its changing status in a CLEAR_ON_RESET
    // transient array, so one preconstructed instance can carry every
    // generated failure without writing persistent memory per frame.
    public static final class StatusWordException extends RuntimeException {
        private final short[] status;

        public StatusWordException(short statusWord) {
            super();
            this.status = JCSystem.makeTransientShortArray(
                    (short) 1, JCSystem.CLEAR_ON_RESET);
            this.status[0] = statusWord;
        }

        public void setStatusWord(short statusWord) {
            // This array is transient RAM; changing status never writes EEPROM.
            this.status[0] = statusWord;
        }

        public short getStatusWord() {
            return status[0];
        }
    }

    /**
     * Generated no-allocation failure path. Arms the one preconstructed
     * StatusWordException with the given status word and returns it, so the
     * caller writes {@code throw statusWordFailure(SW_X);}. Subclasses should
     * use this instead of constructing a fresh StatusWordException on any
     * per-command path: the Java Card heap is never reclaimed.
     */
    protected final StatusWordException statusWordFailure(short statusWord) {
        sharedFailure.setStatusWord(statusWord);
        return sharedFailure;
    }

    private byte[] safeBytes(byte[] data) {
        return data == null ? empty : data;
    }

    // Subtraction after offset validation avoids overflow in offset + length.
    private void checkWindow(byte[] buffer, short offset, short length) {
        if (buffer == null || offset < 0 || length < 0 ||
                offset > buffer.length || length > buffer.length - offset) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
    }

    // Offsets/lengths below are declared int (this file is generated with
    // ints="true" support in the CAP build), but every actual array index is
    // explicitly narrowed to short at the point of use -- the JCVM only
    // accepts short/byte operands for array load/store, even when general
    // int arithmetic is otherwise allowed. This file imports only JCSystem for
    // transient status storage; copies use the short-indexed loop below.
    // The helpers are instance methods (not static) only so their guards can
    // reach the preconstructed exception; a static initializer holding an
    // object is not portable to Java Card Classic.

    protected final int packU8(byte[] buf, int off, byte value) {
        if (buf == null || off < 0 || off >= buf.length) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        buf[(short) off] = value;
        return off + 1;
    }

    protected final int packBool(byte[] buf, int off, boolean value) {
        return packU8(buf, off, (byte) (value ? 0x01 : 0x00));
    }

    protected final int packU16(byte[] buf, int off, short value) {
        if (buf == null || off < 0 || off > buf.length || 2 > buf.length - off) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        buf[(short) off] = (byte) ((value >>> 8) & 0xFF);
        buf[(short) (off+1)] = (byte) (value & 0xFF);
        return off + 2;
    }

    protected final int packU32(byte[] buf, int off, int value) {
        if (buf == null || off < 0 || off > buf.length || 4 > buf.length - off) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        buf[(short) off] = (byte) ((value >>> 24) & 0xFF);
        buf[(short) (off+1)] = (byte) ((value >>> 16) & 0xFF);
        buf[(short) (off+2)] = (byte) ((value >>> 8) & 0xFF);
        buf[(short) (off+3)] = (byte) (value & 0xFF);
        return off + 4;
    }

    protected final int packBytes(byte[] dst, int dstOff, byte[] src, int srcOff, int srcLen) {
        if (dst == null || src == null || srcLen < 0 || dstOff < 0 || srcOff < 0 ||
                dstOff > dst.length || srcOff > src.length ||
                srcLen > dst.length - dstOff || srcLen > src.length - srcOff) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        copyBytes(src, srcOff, dst, dstOff, srcLen);
        return dstOff + srcLen;
    }

    // Manual byte-by-byte copy loop -- neither java.lang.System.arraycopy nor
    // javacard.framework.Util.arrayCopyNonAtomic is available here: System's
    // arraycopy is not part of the real Java Card Classic java.lang.System
    // stub (rejected by the converter: "method arraycopy(...) not found in
    // export file lang.exp"), and Util would require a javacard.framework
    // import, which this file deliberately never has (kept usable as plain
    // JVM code too). A short-indexed loop works identically on both.
    private static void copyBytes(byte[] src, int srcOff, byte[] dst, int dstOff, int len) {
        // memmove semantics for callers echoing a borrowed overlapping span.
        if (src == dst && dstOff > srcOff && dstOff - srcOff < len) {
            for (int i = len - 1; i >= 0; i--) {
                dst[(short) (dstOff + i)] = src[(short) (srcOff + i)];
            }
            return;
        }
        for (int i = 0; i < len; i++) {
            dst[(short) (dstOff + i)] = src[(short) (srcOff + i)];
        }
    }

    private boolean readBool(byte value) {
        if (value == 0x00) {
            return false;
        }
        if (value == 0x01) {
            return true;
        }
        throw statusWordFailure(SW_WRONG_LENGTH);
    }

    private byte readU8(byte[] data, int off) {
        if (off < 0 || off >= data.length) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        return data[(short) off];
    }

    private boolean readBool(byte[] data, int off) {
        return readBool(readU8(data, off));
    }

    private short readU16(byte[] data, int off) {
        if (off < 0 || off+1 >= data.length) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        return (short) (((data[(short) off] & 0xFF) << 8) | (data[(short) (off+1)] & 0xFF));
    }

    private int readU32(byte[] data, int off) {
        if (off < 0 || off+3 >= data.length) {
            throw statusWordFailure(SW_WRONG_LENGTH);
        }
        return ((data[(short) off] & 0xFF) << 24)
            | ((data[(short) (off+1)] & 0xFF) << 16)
            | ((data[(short) (off+2)] & 0xFF) << 8)
            | (data[(short) (off+3)] & 0xFF);
    }

}
`

// javaCodecHelpers names the private decode helpers the skeleton template always
// carries. A schema uses only some of them -- an IDL with no u32 field never
// reads one -- and the unused bodies are dead weight in the converted CAP, which
// on a card is the scarce resource. pruneUnusedJavaCodecHelpers drops the ones
// nothing in the finished source calls.
//
// The protected pack* helpers are deliberately NOT in this list. They are part of
// the skeleton's surface for the hand-written applet that extends it: the counter
// example packs its own response with packU8 and packBool, which the generated
// dispatch never calls. Pruning them would break consumers that the IDL cannot
// see.
var javaCodecHelpers = []string{
	"copyBytes",
	"readBool",
	"readU8",
	"readU16",
	"readU32",
	"slice",
}

// pruneUnusedJavaCodecHelpers removes every codec helper the finished skeleton
// never calls, repeating until nothing more drops out: removing one helper can
// orphan the only caller of another.
func pruneUnusedJavaCodecHelpers(source string) string {
	for {
		removed := false
		for _, name := range javaCodecHelpers {
			blocks := javaHelperBlocks(source, name)
			if len(blocks) == 0 {
				continue
			}
			remainder := source
			for i := len(blocks) - 1; i >= 0; i-- {
				remainder = remainder[:blocks[i][0]] + remainder[blocks[i][1]:]
			}
			if strings.Contains(remainder, name+"(") {
				continue
			}
			for i := len(blocks) - 1; i >= 0; i-- {
				source = source[:blocks[i][0]] + source[blocks[i][1]:]
			}
			removed = true
		}
		if !removed {
			return source
		}
	}
}

// javaHelperBlocks returns the [start, end) span of every declaration of the
// named helper, including the comment lines and blank line that introduce it.
func javaHelperBlocks(source, name string) [][2]int {
	const closing = "\n    }\n"
	var blocks [][2]int
	for offset := 0; offset < len(source); {
		index := javaHelperDeclaration(source, name, offset)
		if index < 0 {
			return blocks
		}
		end := strings.Index(source[index:], closing)
		if end < 0 {
			return blocks
		}
		end += index + len(closing)
		blocks = append(blocks, [2]int{javaHelperBlockStart(source, index), end})
		offset = end
	}
	return blocks
}

// javaHelperDeclaration finds the next line that declares the named helper: a
// method declaration at class-member indentation whose name is followed by the
// parameter list. A call site is indented deeper, so it never matches.
func javaHelperDeclaration(source, name string, offset int) int {
	needle := " " + name + "("
	for search := offset; search < len(source); {
		index := strings.Index(source[search:], needle)
		if index < 0 {
			return -1
		}
		index += search
		lineStart := strings.LastIndexByte(source[:index], '\n') + 1
		line := source[lineStart:index]
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") &&
			(strings.HasPrefix(line, "    private ") || strings.HasPrefix(line, "    protected ")) {
			return lineStart
		}
		search = index + len(needle)
	}
	return -1
}

// javaHelperBlockStart walks back over the comment lines and the blank line that
// introduce a declaration, so removing the method removes its explanation too.
func javaHelperBlockStart(source string, declaration int) int {
	start := declaration
	for start > 0 {
		previous := strings.LastIndexByte(source[:start-1], '\n') + 1
		line := strings.TrimSpace(source[previous : start-1])
		if !strings.HasPrefix(line, "//") {
			break
		}
		start = previous
	}
	if start > 0 && strings.HasSuffix(source[:start], "\n\n") {
		start--
	}
	return start
}

type responseKind int

const (
	responseKindNone responseKind = iota
	responseKindPrimitive
	responseKindBytes
	responseKindPacked
)

type javaTemplateData struct {
	PackageName            string
	AppletName             string
	ClassName              string
	TransportInterfaceName string
	SchemaFileName         string
	CLAHex                 string
	CLAConstName           string
	MethodCommentBlock     string
	INSConstantsBlock      string
	StatusConstantsBlock   string
	DispatchCasesBlock     string
	HandlersBlock          string
	AbstractMethodsBlock   string
	StreamEndpointName     string
	StreamRuntimeName      string
	StreamAPDUAdapterName  string
	// StreamTransientEvent is the JCSystem constant the stream state is allocated
	// with: CLEAR_ON_DESELECT or CLEAR_ON_RESET (see StreamMemory).
	StreamTransientEvent string
	// StreamDigestExternalAccess is the externalAccess argument of the stream
	// digest: "true" with StreamMemoryClearOnReset, "false" otherwise.
	StreamDigestExternalAccess string
	StreamWorkspacePersistent  bool
	StreamCleanupTracked       bool
	StreamCLAMatch             string
}

// StreamMemory selects the transient memory the generated stream state lives in.
type StreamMemory string

const (
	// StreamMemoryClearOnDeselect is the default. The state is reachable only while
	// the applet is the selected one.
	StreamMemoryClearOnDeselect StreamMemory = "clear_on_deselect"
	// StreamMemoryClearOnReset keeps the state reachable while another application
	// is selected, which is when a Security Domain forwards STORE DATA to the
	// applet through org.globalplatform.Personalization.processData. The stream
	// digest is then created with externalAccess true, because a MessageDigest
	// created with false may not be used while its owner is not selected. The
	// owning applet must still call the adapter's deselect() from its deselect
	// callback; that is what empties the state on deselect, and a card reset
	// empties it too.
	StreamMemoryClearOnReset StreamMemory = "clear_on_reset"
)

// JavaOptions are generation choices that do not change the wire contract.
type JavaOptions struct {
	StreamMemory StreamMemory
}

func (o JavaOptions) streamTransientEvent() (event, digestExternalAccess string, err error) {
	switch o.StreamMemory {
	case "", StreamMemoryClearOnDeselect:
		return "CLEAR_ON_DESELECT", "false", nil
	case StreamMemoryClearOnReset:
		return "CLEAR_ON_RESET", "true", nil
	default:
		return "", "", fmt.Errorf("unknown stream memory %q: expected %q or %q", o.StreamMemory, StreamMemoryClearOnDeselect, StreamMemoryClearOnReset)
	}
}

type javaMethodRender struct {
	Name                     string
	INS                      byte
	INSConstName             string
	HandlerName              string
	AbstractName             string
	Signature                string
	HasHandler               bool
	HandlerLines             []string
	HandlerParams            []string
	AbstractReturn           string
	AbstractParams           []string
	ResponseKind             responseKind
	IsStream                 bool
	RequestStream            *Field
	ResponseStream           *Field
	ExactShortResponseLength int
}

type requestHandling struct {
	Lines      []string
	ArgExprs   []string
	ParamDecls []string
	Comment    string
}

// JavaGenerationResult holds the generated Java source files.
type JavaGenerationResult struct {
	TransportSource         []byte // CounterTransport.java
	SkeletonSource          []byte // CounterSkeleton.java
	StreamEndpointSource    []byte // CounterStreamEndpoint.java, streamed schemas only
	StreamRuntimeSource     []byte // CounterBoundedStreamRuntime.java, streamed schemas only
	StreamAPDUAdapterSource []byte // CounterStreamAPDUAdapter.java, streamed schemas only
	TransportName           string // e.g. "CounterTransport"
	SkeletonName            string // e.g. "CounterSkeleton"
	StreamEndpointName      string // e.g. "CounterStreamEndpoint"
	StreamRuntimeName       string // e.g. "CounterBoundedStreamRuntime"
	StreamAPDUAdapterName   string // e.g. "CounterStreamAPDUAdapter"
}

// GenerateJavaSkeleton renders a Java Card abstract applet skeleton from a validated schema,
// with the default options.
func GenerateJavaSkeleton(s *Schema, packageName string) (*JavaGenerationResult, error) {
	return GenerateJavaSkeletonWithOptions(s, packageName, JavaOptions{})
}

// GenerateJavaSkeletonWithOptions is GenerateJavaSkeleton with explicit generation options.
func GenerateJavaSkeletonWithOptions(s *Schema, packageName string, options JavaOptions) (*JavaGenerationResult, error) {
	streamEvent, streamDigestExternalAccess, err := options.streamTransientEvent()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("schema is nil")
	}
	if s.Applet.StreamWorkspace != "" && s.Applet.StreamWorkspace != "transient" && s.Applet.StreamWorkspace != "persistent" {
		return nil, fmt.Errorf("unknown stream workspace %q: expected transient or persistent", s.Applet.StreamWorkspace)
	}
	switch s.Applet.StreamWorkspaceCleanup {
	case "":
	case pluginapi.StreamWorkspaceCleanupWholeReplyArea:
		if s.Applet.StreamWorkspace != "persistent" {
			return nil, fmt.Errorf("stream workspace cleanup requires persistent stream workspace")
		}
	default:
		return nil, fmt.Errorf("unknown stream workspace cleanup %q", s.Applet.StreamWorkspaceCleanup)
	}
	if strings.TrimSpace(packageName) == "" {
		return nil, fmt.Errorf("package name is empty")
	}

	methods, err := renderMethods(s)
	if err != nil {
		return nil, err
	}

	data := javaTemplateData{
		PackageName:               strings.TrimSpace(packageName),
		AppletName:                strings.TrimSpace(s.Applet.Name),
		ClassName:                 toPascal(s.Applet.Name) + "Skeleton",
		TransportInterfaceName:    toPascal(s.Applet.Name) + "Transport",
		SchemaFileName:            strings.ToLower(strings.TrimSpace(s.Applet.Name)) + ".toml",
		CLAHex:                    fmt.Sprintf("%02X", s.Applet.CLA),
		CLAConstName:              "CLA_" + toUpperSnake(s.Applet.Name),
		MethodCommentBlock:        buildMethodCommentBlock(methods),
		INSConstantsBlock:         buildINSConstantsBlock(methods),
		StatusConstantsBlock:      buildStatusConstantsBlock(s.StatusWords),
		DispatchCasesBlock:        buildDispatchCasesBlock(methods),
		HandlersBlock:             buildHandlersBlock(methods),
		AbstractMethodsBlock:      buildAbstractMethodsBlock(methods),
		StreamEndpointName:        toPascal(s.Applet.Name) + "StreamEndpoint",
		StreamRuntimeName:         toPascal(s.Applet.Name) + "BoundedStreamRuntime",
		StreamAPDUAdapterName:     toPascal(s.Applet.Name) + "StreamAPDUAdapter",
		StreamTransientEvent:      streamEvent,
		StreamWorkspacePersistent: s.Applet.StreamWorkspace == "persistent",
		StreamCleanupTracked:      s.Applet.StreamWorkspaceCleanup != "",
		StreamCLAMatch:            javaStreamCLAMatch(s.Applet.CLA),

		StreamDigestExternalAccess: streamDigestExternalAccess,
	}

	// Render transport interface
	transportTpl, err := template.New("java_transport").Parse(javaTransportTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse java transport template: %w", err)
	}
	var transportOut bytes.Buffer
	if err := transportTpl.Execute(&transportOut, data); err != nil {
		return nil, fmt.Errorf("render java transport: %w", err)
	}

	// Render skeleton
	skeletonTpl, err := template.New("java_skeleton").Parse(javaSkeletonTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse java skeleton template: %w", err)
	}
	var skeletonOut bytes.Buffer
	if err := skeletonTpl.Execute(&skeletonOut, data); err != nil {
		return nil, fmt.Errorf("render java skeleton: %w", err)
	}

	streamEndpointSource, streamRuntimeSource, streamAPDUAdapterSource, err := generateJavaStreamSupport(&data, methods)
	if err != nil {
		return nil, err
	}
	if len(streamEndpointSource) > 0 {
		augmented, augmentErr := augmentJavaSkeletonForStreams(skeletonOut.String(), &data, methods)
		if augmentErr != nil {
			return nil, augmentErr
		}
		skeletonOut.Reset()
		skeletonOut.WriteString(augmented)
	}

	return &JavaGenerationResult{
		TransportSource:         transportOut.Bytes(),
		SkeletonSource:          []byte(pruneUnusedJavaCodecHelpers(skeletonOut.String())),
		StreamEndpointSource:    streamEndpointSource,
		StreamRuntimeSource:     streamRuntimeSource,
		StreamAPDUAdapterSource: streamAPDUAdapterSource,
		TransportName:           data.TransportInterfaceName,
		SkeletonName:            data.ClassName,
		StreamEndpointName:      data.StreamEndpointName,
		StreamRuntimeName:       data.StreamRuntimeName,
		StreamAPDUAdapterName:   data.StreamAPDUAdapterName,
	}, nil
}

func renderMethods(s *Schema) ([]javaMethodRender, error) {
	type methodEntry struct {
		Name   string
		Method *Method
	}

	entries := make([]methodEntry, 0, len(s.Methods))
	for key, method := range s.Methods {
		if method == nil {
			return nil, fmt.Errorf("methods.%s: method definition is nil", key)
		}
		name := strings.TrimSpace(method.Name)
		if name == "" {
			name = key
		}
		entries = append(entries, methodEntry{Name: name, Method: method})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Method.INS == entries[j].Method.INS {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Method.INS < entries[j].Method.INS
	})

	rendered := make([]javaMethodRender, 0, len(entries))
	for _, entry := range entries {
		m, err := renderMethod(entry.Name, entry.Method)
		if err != nil {
			return nil, fmt.Errorf("methods.%s: %w", entry.Name, err)
		}
		rendered = append(rendered, m)
	}

	return rendered, nil
}

func renderMethod(name string, m *Method) (javaMethodRender, error) {
	mr := javaMethodRender{
		Name:         name,
		INS:          m.INS,
		INSConstName: "INS_" + toUpperSnake(name),
		HandlerName:  "handle" + toPascal(name),
		AbstractName: "on" + toPascal(name),
		Signature:    methodSignature(name, m),
	}
	if m.HasStream() {
		mr.IsStream = true
		mr.RequestStream = m.Request.StreamField()
		mr.ResponseStream = m.Response.StreamField()
		mr.ExactShortResponseLength = -1
		if mr.ResponseStream == nil {
			if length, fixed := fixedMessageLength(responseFields(m.Response)); fixed {
				mr.ExactShortResponseLength = length
			}
		}
		return mr, nil
	}

	names := newOrdinaryJavaNames(m.Request)
	request, err := buildRequestHandling(m.Request, names)
	if err != nil {
		return javaMethodRender{}, err
	}

	fields := responseFields(m.Response)
	mr.AbstractParams = request.ParamDecls
	mr.HasHandler = true
	width, fixed := fixedMessageLength(fields)
	lines := []string{}
	if fixed {
		lines = append(lines, fmt.Sprintf("if (%s < %d) {", names.outputCapacity, width), "    throw statusWordFailure(SW_WRONG_LENGTH);", "}")
	}
	args := strings.Join(request.ArgExprs, ", ")
	call := fmt.Sprintf("%s(%s)", mr.AbstractName, args)
	switch {
	case len(fields) == 0:
		mr.AbstractReturn = "void"
		mr.ResponseKind = responseKindNone
		lines = append(lines, call+";", "return (short) 0;")
	case len(fields) == 1 && (fields[0].Type == FieldTypeU8 || fields[0].Type == FieldTypeBool || fields[0].Type == FieldTypeU16 || fields[0].Type == FieldTypeU32):
		mr.ResponseKind = responseKindPrimitive
		codec := ""
		switch fields[0].Type {
		case FieldTypeU8:
			mr.AbstractReturn, codec = "byte", "packU8"
		case FieldTypeBool:
			mr.AbstractReturn, codec = "boolean", "packBool"
		case FieldTypeU16:
			mr.AbstractReturn, codec = "short", "packU16"
		case FieldTypeU32:
			mr.AbstractReturn, codec = "int", "packU32"
		}
		lines = append(lines, fmt.Sprintf("%s %s = %s;", mr.AbstractReturn, names.result, call), fmt.Sprintf("%s(%s, %s, %s);", codec, names.output, names.outputOffset, names.result), fmt.Sprintf("return (short) %d;", width))
	default:
		mr.AbstractReturn = "short"
		mr.ResponseKind = responseKindPacked
		if len(fields) == 1 && isByteSequenceField(fields[0]) {
			mr.ResponseKind = responseKindBytes
		}
		mr.AbstractParams = append(mr.AbstractParams, "byte[] "+names.output, "short "+names.outputOffset, "short "+names.outputCapacity)
		if args != "" {
			args += ", "
		}
		capacity := names.outputCapacity
		if fixed {
			capacity = fmt.Sprintf("(short) %d", width)
		}
		lines = append(lines, fmt.Sprintf("short %s = %s(%s%s, %s, %s);", names.produced, mr.AbstractName, args, names.output, names.outputOffset, capacity), fmt.Sprintf("if (%s < 0 || %s > %s) {", names.produced, names.produced, names.outputCapacity), "    throw statusWordFailure(SW_WRONG_LENGTH);", "}")
		if fixed {
			lines = append(lines, fmt.Sprintf("if (%s != %d) {", names.produced, width), "    throw statusWordFailure(SW_WRONG_LENGTH);", "}")
		}
		lines = append(lines, "return "+names.produced+";")
	}
	mr.HandlerLines = appendHandlerBody(request, lines...)
	mr.HandlerParams = []string{"byte " + names.p1, "byte " + names.p2, "byte[] " + names.requestData, "short " + names.requestOffset, "short " + names.requestLength, "byte[] " + names.output, "short " + names.outputOffset, "short " + names.outputCapacity}
	return mr, nil
}

// Reserve the COMPLETE user namespace before choosing any generated name. A
// later field can collide with an earlier field's Offset/Length companion, and
// suffixes themselves are valid IDL names. Each allocation is reserved in turn.
type ordinaryJavaNames struct {
	used                                                   map[string]bool
	p1, p2, requestData, requestOffset, requestLength      string
	output, outputOffset, outputCapacity, result, produced string
}

func newOrdinaryJavaNames(msg *Message) *ordinaryJavaNames {
	n := &ordinaryJavaNames{used: map[string]bool{}}
	if msg != nil {
		for _, f := range msg.Fields {
			n.used[f.Name] = true
		}
	}
	n.p1, n.p2 = n.take("p1"), n.take("p2")
	n.requestData, n.requestOffset, n.requestLength = n.take("requestData"), n.take("requestOffset"), n.take("requestLength")
	n.output, n.outputOffset, n.outputCapacity = n.take("output"), n.take("outputOffset"), n.take("outputCapacity")
	n.result, n.produced = n.take("result"), n.take("produced")
	return n
}

func (n *ordinaryJavaNames) take(base string) string {
	name := base
	for suffix := 1; n.used[name]; suffix++ {
		name = fmt.Sprintf("%s_%d", base, suffix)
	}
	n.used[name] = true
	return name
}

func buildRequestHandling(msg *Message, names *ordinaryJavaNames) (requestHandling, error) {
	rh := requestHandling{}
	if msg == nil || len(msg.Fields) == 0 {
		rh.Lines = []string{fmt.Sprintf("if (%s != 0) {", names.requestLength), "    throw statusWordFailure(SW_WRONG_LENGTH);", "}"}
		return rh, nil
	}

	fields := msg.Fields
	rh.Comment = requestComment(fields)

	variableFieldIndex := -1
	fixedDataLen := 0

	for i, f := range fields {
		switch f.Location {
		case ParameterLocationP1, ParameterLocationP2:
			if !isP1P2FieldType(f.Type) {
				return requestHandling{}, fmt.Errorf("%s field must be u8 or bool", f.Location)
			}
		case ParameterLocationData, ParameterLocationNone:
			switch f.Type {
			case FieldTypeU8, FieldTypeBool:
				fixedDataLen++
			case FieldTypeU16:
				fixedDataLen += 2
			case FieldTypeU32:
				fixedDataLen += 4
			case FieldTypeBytesFixed:
				if f.FixedLength <= 0 {
					return requestHandling{}, fmt.Errorf("fixed bytes request field %q must have length > 0", f.Name)
				}
				fixedDataLen += f.FixedLength
			case FieldTypeASCII, FieldTypeString, FieldTypeBytes:
				if f.Type == FieldTypeString && f.Length != nil {
					return requestHandling{}, fmt.Errorf("string request field %q does not support fixed length", f.Name)
				}
				if f.Length != nil {
					fixedDataLen += *f.Length
					break
				}
				if variableFieldIndex != -1 {
					return requestHandling{}, fmt.Errorf("multiple variable-length request fields are unsupported")
				}
				variableFieldIndex = i
			default:
				return requestHandling{}, fmt.Errorf("unsupported request field type %q", f.Type)
			}
		default:
			return requestHandling{}, fmt.Errorf("unsupported request field location %q", f.Location)
		}
	}

	if variableFieldIndex != -1 {
		for i := variableFieldIndex + 1; i < len(fields); i++ {
			if fields[i].Location == ParameterLocationData || fields[i].Location == ParameterLocationNone {
				return requestHandling{}, fmt.Errorf("variable-length request field must be last among data fields")
			}
		}
	}

	comparison := "!="
	if variableFieldIndex != -1 {
		comparison = "<"
	}
	rh.Lines = append(rh.Lines, fmt.Sprintf("if (%s %s %d) {", names.requestLength, comparison, fixedDataLen), "    throw statusWordFailure(SW_WRONG_LENGTH);", "}")

	dataOffset := 0
	for _, f := range fields {
		switch f.Location {
		case ParameterLocationP1:
			switch f.Type {
			case FieldTypeU8:
				rh.ParamDecls = append(rh.ParamDecls, "byte "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("byte %s = %s;", f.Name, names.p1))
			case FieldTypeBool:
				rh.ParamDecls = append(rh.ParamDecls, "boolean "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("boolean %s = readBool(%s);", f.Name, names.p1))
			default:
				return requestHandling{}, fmt.Errorf("unsupported request field type %q", f.Type)
			}
		case ParameterLocationP2:
			switch f.Type {
			case FieldTypeU8:
				rh.ParamDecls = append(rh.ParamDecls, "byte "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("byte %s = %s;", f.Name, names.p2))
			case FieldTypeBool:
				rh.ParamDecls = append(rh.ParamDecls, "boolean "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("boolean %s = readBool(%s);", f.Name, names.p2))
			default:
				return requestHandling{}, fmt.Errorf("unsupported request field type %q", f.Type)
			}
		case ParameterLocationData, ParameterLocationNone:
			switch f.Type {
			case FieldTypeU8:
				rh.ParamDecls = append(rh.ParamDecls, "byte "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("byte %s = readU8(%s, %s + %d);", f.Name, names.requestData, names.requestOffset, dataOffset))
				dataOffset++
			case FieldTypeBool:
				rh.ParamDecls = append(rh.ParamDecls, "boolean "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("boolean %s = readBool(%s, %s + %d);", f.Name, names.requestData, names.requestOffset, dataOffset))
				dataOffset++
			case FieldTypeU16:
				rh.ParamDecls = append(rh.ParamDecls, "short "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("short %s = readU16(%s, %s + %d);", f.Name, names.requestData, names.requestOffset, dataOffset))
				dataOffset += 2
			case FieldTypeU32:
				rh.ParamDecls = append(rh.ParamDecls, "int "+f.Name)
				rh.ArgExprs = append(rh.ArgExprs, f.Name)
				rh.Lines = append(rh.Lines, fmt.Sprintf("int %s = readU32(%s, %s + %d);", f.Name, names.requestData, names.requestOffset, dataOffset))
				dataOffset += 4
			case FieldTypeBytesFixed, FieldTypeASCII, FieldTypeString, FieldTypeBytes:
				offsetName, lengthName := names.take(f.Name+"Offset"), names.take(f.Name+"Length")
				rh.ParamDecls = append(rh.ParamDecls, "byte[] "+f.Name, "short "+offsetName, "short "+lengthName)
				rh.ArgExprs = append(rh.ArgExprs, names.requestData, offsetName, lengthName)
				length := fmt.Sprintf("(short) (%s - %d)", names.requestLength, dataOffset)
				if n, ok := byteSequenceFixedLength(f); ok {
					length = fmt.Sprintf("(short) %d", n)
				}
				rh.Lines = append(rh.Lines, fmt.Sprintf("short %s = (short) (%s + %d);", offsetName, names.requestOffset, dataOffset), fmt.Sprintf("short %s = %s;", lengthName, length))
				if n, ok := byteSequenceFixedLength(f); ok {
					dataOffset += n
				}

			default:
				return requestHandling{}, fmt.Errorf("unsupported request field type %q", f.Type)
			}
		default:
			return requestHandling{}, fmt.Errorf("unsupported request field location %q", f.Location)
		}
	}

	return rh, nil
}

func appendHandlerBody(request requestHandling, lines ...string) []string {
	out := make([]string, 0, len(request.Lines)+len(lines)+1)
	if request.Comment != "" {
		out = append(out, "// "+request.Comment)
	}
	out = append(out, request.Lines...)
	out = append(out, lines...)
	return out
}

func buildMethodCommentBlock(methods []javaMethodRender) string {
	var b strings.Builder
	for _, method := range methods {
		if method.IsStream {
			fmt.Fprintf(&b, " *   INS 0x%02X..0x%02X — %s\n", method.INS, method.INS+5, method.Signature)
		} else {
			fmt.Fprintf(&b, " *   INS 0x%02X — %s\n", method.INS, method.Signature)
		}
	}
	return b.String()
}

func buildINSConstantsBlock(methods []javaMethodRender) string {
	type insEntry struct {
		name string
		ins  byte
	}
	entries := make([]insEntry, 0, len(methods))
	streamSuffixes := []string{
		"WRITE_OR_INVOKE",
		"CLOSE_WRITE",
		"GET_PENDING_READ_INFO",
		"READ_CHUNK",
		"CLOSE_READ",
		"ABORT",
	}
	for _, method := range methods {
		if !method.IsStream {
			entries = append(entries, insEntry{name: method.INSConstName, ins: method.INS})
			continue
		}
		for offset, suffix := range streamSuffixes {
			entries = append(entries, insEntry{
				name: method.INSConstName + "_" + suffix,
				ins:  method.INS + byte(offset),
			})
		}
	}

	maxLen := 0
	for _, entry := range entries {
		if len(entry.name) > maxLen {
			maxLen = len(entry.name)
		}
	}

	var b strings.Builder
	for _, entry := range entries {
		padding := strings.Repeat(" ", maxLen-len(entry.name)+2)
		fmt.Fprintf(&b, "    private static final byte %s%s= (byte) 0x%02X;\n", entry.name, padding, entry.ins)
	}
	if b.Len() > 0 {
		trimmed := strings.TrimSuffix(b.String(), "\n")
		return trimmed
	}
	return ""
}

func buildStatusConstantsBlock(statusWords map[string]StatusWord) string {
	type statusEntry struct {
		Name string
		Code uint16
	}
	entries := make([]statusEntry, 0, len(statusWords))
	for key, sw := range statusWords {
		name := strings.TrimSpace(sw.Name)
		if name == "" {
			name = key
		}
		entries = append(entries, statusEntry{Name: name, Code: sw.Code})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].Code < entries[j].Code
		}
		return entries[i].Name > entries[j].Name
	})

	maxLen := 0
	for _, entry := range entries {
		if len(entry.Name) > maxLen {
			maxLen = len(entry.Name)
		}
	}

	var b strings.Builder
	for _, entry := range entries {
		padding := strings.Repeat(" ", maxLen-len(entry.Name)+1)
		fmt.Fprintf(&b, "    public static final short %s%s= (short) 0x%04X;\n", entry.Name, padding, entry.Code)
	}
	if b.Len() > 0 {
		trimmed := strings.TrimSuffix(b.String(), "\n")
		return trimmed
	}
	return ""
}

func buildDispatchCasesBlock(methods []javaMethodRender) string {
	var b strings.Builder
	for _, method := range methods {
		if method.IsStream {
			continue
		}
		fmt.Fprintf(&b, "            case %s:\n", method.INSConstName)
		if method.HasHandler {
			fmt.Fprintf(&b, "                return %s(p1, p2, requestData, requestOffset, requestLength, output, outputOffset, outputCapacity);\n", method.HandlerName)
		} else {
			fmt.Fprintf(&b, "                %s();\n", method.AbstractName)
			b.WriteString("                return (short) 0;\n")
		}
	}
	return b.String()
}

func buildHandlersBlock(methods []javaMethodRender) string {
	var b strings.Builder
	for _, method := range methods {
		if method.IsStream || !method.HasHandler {
			continue
		}
		fmt.Fprintf(&b, "    private short %s(%s) {\n", method.HandlerName, strings.Join(method.HandlerParams, ", "))
		for _, line := range method.HandlerLines {
			fmt.Fprintf(&b, "        %s\n", line)
		}
		b.WriteString("    }\n\n")
	}
	return b.String()
}

func buildAbstractMethodsBlock(methods []javaMethodRender) string {
	var b strings.Builder
	nonStreamCount := 0
	for _, method := range methods {
		if !method.IsStream {
			nonStreamCount++
		}
	}
	written := 0
	for _, method := range methods {
		if method.IsStream {
			continue
		}
		switch method.ResponseKind {
		case responseKindPacked:
			fmt.Fprintf(&b, "    /**\n")
			fmt.Fprintf(&b, "     * %s\n", method.Signature)
			fmt.Fprintf(&b, "     * Write encoded response bytes in schema field order; return produced length.\n")
			fmt.Fprintf(&b, "     */\n")
		case responseKindBytes:
			fmt.Fprintf(&b, "    /**\n")
			fmt.Fprintf(&b, "     * %s\n", method.Signature)
			fmt.Fprintf(&b, "     * Write response bytes into the output span; return produced length.\n")
			fmt.Fprintf(&b, "     */\n")
		default:
			fmt.Fprintf(&b, "    /** %s */\n", method.Signature)
		}
		fmt.Fprintf(
			&b,
			"    protected abstract %s %s(%s);\n",
			method.AbstractReturn,
			method.AbstractName,
			strings.Join(method.AbstractParams, ", "),
		)
		written++
		if written != nonStreamCount {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func requestComment(fields []Field) string {
	if len(fields) == 0 {
		return ""
	}

	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		location := "data"
		switch f.Location {
		case ParameterLocationP1:
			location = "P1"
		case ParameterLocationP2:
			location = "P2"
		case ParameterLocationData, ParameterLocationNone:
			if isByteSequenceField(f) {
				location = "request data"
			}
		}
		parts = append(parts, fmt.Sprintf("%s(%s) in %s", f.Name, f.Type, location))
	}
	return "request: " + strings.Join(parts, ", ")
}

func methodSignature(name string, m *Method) string {
	var b strings.Builder

	b.WriteString(name)
	b.WriteString("(")
	requestFields := requestFields(m.Request)
	for i, f := range requestFields {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %s", f.Name, f.Type)
	}
	b.WriteString(")")

	responseFields := responseFields(m.Response)
	switch len(responseFields) {
	case 0:
		return b.String()
	case 1:
		fmt.Fprintf(&b, " → %s: %s", responseFields[0].Name, responseFields[0].Type)
		return b.String()
	default:
		b.WriteString(" → {")
		for i, f := range responseFields {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s: %s", f.Name, f.Type)
		}
		b.WriteString("}")
		return b.String()
	}
}

func requestFields(msg *Message) []Field {
	if msg == nil {
		return nil
	}
	return msg.Fields
}

func responseFields(msg *Message) []Field {
	if msg == nil {
		return nil
	}
	return msg.Fields
}

func isByteSequenceField(f Field) bool {
	return f.Type == FieldTypeASCII || f.Type == FieldTypeString || f.Type == FieldTypeBytes || f.Type == FieldTypeBytesFixed
}

func byteSequenceFixedLength(f Field) (int, bool) {
	switch f.Type {
	case FieldTypeBytesFixed:
		return f.FixedLength, f.FixedLength > 0
	case FieldTypeASCII, FieldTypeBytes:
		if f.Length != nil && *f.Length > 0 {
			return *f.Length, true
		}
	}
	return 0, false
}

func toPascal(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	parts := splitIdentifierParts(s)
	if len(parts) == 0 {
		return ""
	}

	var b strings.Builder
	for _, part := range parts {
		runes := []rune(part)
		if len(runes) == 0 {
			continue
		}
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	return b.String()
}

func toUpperSnake(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	parts := splitIdentifierParts(s)
	if len(parts) == 0 {
		return ""
	}

	for i, part := range parts {
		parts[i] = strings.ToUpper(part)
	}
	return strings.Join(parts, "_")
}

func splitIdentifierParts(s string) []string {
	runes := []rune(s)
	if len(runes) == 0 {
		return nil
	}

	parts := make([]string, 0, 4)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			parts = append(parts, string(runes[start:end]))
		}
		start = -1
	}

	for i, r := range runes {
		isAlphaNum := unicode.IsLetter(r) || unicode.IsDigit(r)
		if !isAlphaNum {
			flush(i)
			continue
		}
		if start == -1 {
			start = i
			continue
		}

		prev := runes[i-1]
		boundary := false
		if unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev)) {
			boundary = true
		} else if unicode.IsDigit(r) && unicode.IsLetter(prev) {
			boundary = true
		} else if unicode.IsLetter(r) && unicode.IsDigit(prev) {
			boundary = true
		} else if unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
			boundary = true
		}

		if boundary {
			flush(i)
			start = i
		}
	}
	flush(len(runes))
	return parts
}
