package io.jcrpc.modestore.server;

import javacard.framework.*;
import com.licel.jcardsim.base.*;
import java.lang.reflect.*;
import java.util.*;
import java.security.MessageDigest;

/**
 * Drives Simulator.transmitCommand -> ModeStoreApplet.process -> generated
 * processIfStream (adapter route) or dispatchStreamTo (direct route) ->
 * generated runtime dispatch. Every APDU asserts its status word and its
 * logical persistent store count; each refusal is followed by a check that the
 * refused stream is dead and by a nearby accepted control.
 */
public class ModeStoreHarness {
    static Simulator simulator;
    static AID aid, other;
    static byte[] workspace;
    static String route;
    static final byte[] EMPTY = new byte[0];

    // INS families.
    static final int PREVIEW = 0x13, INSPECT = 0x23, PUT = 0x33, WINDOW = 0x43, PUBLIC_RECEIPT = 0x53;
    static final int WRITE = 0, CLOSE = 1, INFO = 2, READ = 3, CLOSE_READ = 4, ABORT = 5;

    public static void main(String[] args) throws Exception {
        simulator = new Simulator();
        aid = new AID(new byte[] {(byte) 0xF0, 0, 0, 1, 4, 1}, (short) 0, (byte) 6);
        other = new AID(new byte[] {(byte) 0xF0, 0, 0, 1, 4, 2}, (short) 0, (byte) 6);
        simulator.installApplet(aid, ModeStoreApplet.class);
        simulator.installApplet(other, EmptyApplet.class);
        simulator.selectApplet(aid);
        Object session = field(ModeStoreApplet.installed.logic, "streamSession");
        workspace = (byte[]) field(session, "workspace");
        // Ledger classification control: the workspace is persistent, a transient array is not.
        NvmLedger.reset();
        NvmLedger.store(workspace);
        NvmLedger.store(JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET));
        if (NvmLedger.persistent != 1 || NvmLedger.transientStores != 1) throw new AssertionError("ledger classification control");
        String only = args.length > 0 ? args[0] : "all";
        for (boolean direct : new boolean[] {false, true}) {
            ModeStoreApplet.direct = direct;
            route = direct ? "direct" : "adapter";
            if (only.equals("all") || only.equals("chunked")) chunked();
            if (only.equals("all") || only.equals("public")) publicStreams();
            if (only.equals("all") || only.equals("record transfer")) recordStreams();
            if (only.equals("all") || only.equals("authority")) authority();
            if (only.equals("all") || only.equals("invalidation")) publicInvalidation();
            if (only.equals("all") || only.equals("bounds")) requestBounds();
            if (direct && (only.equals("all") || only.equals("spans"))) spanRecordTransfer();
        }
        runtimeRefusals(session);
        System.out.println("stream modes: chunked offset summary, circular storage window, public page preview, authority and span controls green on adapter and direct routes");
    }

    // ---------------------------------------------------------------- chunked

    static void chunked() throws Exception {
        reset();
        auth(false); // chunked methods are public: no authentication is required
        byte[] t = offsets(194);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, t.length);
        byte[] before = workspace.clone();
        int calls = ModeStoreApplet.chunkCalls;
        ModeStoreApplet.maxChunk = 0;
        ModeStoreApplet.chunkFromPersistent = false;
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked first chunk wrote persistent");
        expect(0x9000, INSPECT, 1, 2, b, 0, "chunked last chunk wrote persistent");
        byte[] summary = expect(0x9000, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked close wrote persistent");
        if (summary.length != 6) throw new AssertionError("chunked response is not one 6 B response: " + summary.length);
        checkSummary(summary, t, "chunked summary does not describe every offset");
        if (!Arrays.equals(before, workspace)) throw new AssertionError("chunked session staged the request");
        if (ModeStoreApplet.chunkCalls - calls != 2 || ModeStoreApplet.maxChunk != 192)
            throw new AssertionError("chunked handler did not receive each chunk once");
        if (ModeStoreApplet.chunkFromPersistent) throw new AssertionError("chunk delivered from persistent memory");
        // No receipt is retained: a CLOSE retry finds no session.
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked close retry wrote persistent");

        // Declared bound: 1024 B in six chunks, still 0 B persistent on every APDU.
        byte[] max = offsets(1024);
        before = workspace.clone();
        calls = ModeStoreApplet.chunkCalls;
        for (int i = 0; i < 6; i++) {
            expect(0x9000, INSPECT, i, 6, part(max, i), 0, "chunked bounded chunk wrote persistent");
        }
        checkSummary(expect(0x9000, INSPECT + CLOSE, 0, 0, close(max), 0, "chunked bounded close wrote persistent"), max,
                "chunked bounded summary");
        if (!Arrays.equals(before, workspace) || ModeStoreApplet.chunkCalls - calls != 6)
            throw new AssertionError("chunked bounded session staged the request");
        expect(0x6700, INSPECT, 0, 7, a, 0, "chunked oversized declaration wrote persistent");

        // Chunk order: a skipped index is refused and kills the stream.
        byte[] t3 = offsets(400);
        expect(0x9000, INSPECT, 0, 3, part(t3, 0), 0, "chunked order control");
        expect(0x6A80, INSPECT, 2, 3, part(t3, 2), 0, "chunked out-of-order chunk wrote persistent");
        expect(0x6A80, INSPECT, 1, 3, part(t3, 1), 0, "chunked retry after order refusal wrote persistent");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t3), 0, "chunked order refusal retained live handle");
        inspectSession(t3, "chunked fresh session after order refusal");

        // Duplicates: nothing is staged, so any repeat is refused, changed or not.
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked duplicate control");
        byte[] changed = a.clone();
        changed[100] ^= 1;
        expect(0x6A80, INSPECT, 0, 2, changed, 0, "chunked changed duplicate wrote persistent");
        // The next chunk at the stream's expected index: a live stream accepts it.
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked changed duplicate left a live stream");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked changed duplicate retained live handle");
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked identical duplicate control");
        expect(0x6A80, INSPECT, 0, 2, a, 0, "chunked identical duplicate wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked identical duplicate retained live handle");

        // Invalid lengths and close declarations.
        expect(0x6700, INSPECT, 0, 2, Arrays.copyOf(a, 100), 0, "chunked short middle chunk wrote persistent");
        // Mid-stream shape refusal: the valid chunk at the same index must find
        // a dead stream (6A80); a live stream would accept it with 9000.
        expect(0x9000, INSPECT, 0, 3, part(t3, 0), 0, "chunked mid-stream shape control");
        expect(0x6700, INSPECT, 1, 3, Arrays.copyOf(part(t3, 1), 100), 0, "chunked mid-stream short chunk wrote persistent");
        expect(0x6A80, INSPECT, 1, 3, part(t3, 1), 0, "chunked short middle refusal left a live stream");
        inspectSession(t3, "chunked fresh session after shape refusal");
        sendChunks(t, "chunked close length control");
        byte[] wrongLength = close(t);
        wrongLength[1] ^= 1;
        expect(0x6700, INSPECT + CLOSE, 0, 0, wrongLength, 0, "chunked close length wrote persistent");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked close length refusal retained live handle");
        sendChunks(t, "chunked close digest control");
        byte[] wrongDigest = close(t);
        wrongDigest[33] ^= 1;
        expect(0x6A80, INSPECT + CLOSE, 0, 0, wrongDigest, 0, "chunked bad close digest wrote persistent");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked bad digest retained live handle");
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked early close control");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked early close wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked early close retained live handle");
        sendChunks(t, "chunked short close control");
        expect(0x6700, INSPECT + CLOSE, 0, 0, Arrays.copyOf(close(t), 33), 0, "chunked short close wrote persistent");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked short close retained live handle");

        // Abort, reset and deselect: 0 B and a dead stream; a fresh session works.
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked abort control");
        expect(0x9000, INSPECT + ABORT, 0, 0, EMPTY, 0, "chunked abort wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked abort retained live handle");
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked reset control");
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked post-reset close wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked post-reset retry wrote persistent");
        inspectSession(t, "chunked fresh session after reset");
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked deselect control");
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": chunked deselect wrote persistent");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked deselect retained live handle");

        // Foreign method: refused with 0 B and the chunked stream is dead.
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked foreign control");
        auth(true);
        expect(0x6985, PUT, 0, 1, b, 0, "chunked foreign method wrote persistent");
        auth(false);
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked foreign refusal retained live handle");
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked foreign read control");
        expect(0x6985, WINDOW + READ, 0, 1, EMPTY, 0, "chunked foreign read wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked foreign read retained live handle");

        // Handler failures: reserved seek, mid-stream, finish after output, bad length.
        byte[] reservedSeek = t.clone();
        reservedSeek[0] = reservedSeek[1] = (byte) 0xFF;
        expect(0x6A80, INSPECT, 0, 2, Arrays.copyOf(reservedSeek, 192), 0, "chunked reserved seek refusal wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked reserved seek refusal retained live handle");
        ModeStoreApplet.control = 3;
        expect(0x9000, INSPECT, 0, 2, a, 0, "chunked handler failure control");
        expect(0x6F00, INSPECT, 1, 2, b, 0, "chunked handler chunk failure wrote persistent");
        // The failed chunk again, with the handler healthy: a live stream accepts it.
        ModeStoreApplet.control = 0;
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked handler chunk failure left a live stream");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked handler failure retained live handle");
        ModeStoreApplet.control = 1;
        sendChunks(t, "chunked finish failure control");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked finish failure wrote persistent");
        if (NvmLedger.apduStores + NvmLedger.transientStores < 6) throw new AssertionError("failing finish did not write its output");
        ModeStoreApplet.control = 2;
        sendChunks(t, "chunked invalid length control");
        expect(0x6700, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked invalid result length wrote persistent");
        ModeStoreApplet.control = 0;
        byte[] partialWord = Arrays.copyOf(t, t.length - 1);
        sendChunks(partialWord, "chunked partial seek control");
        expect(0x6A80, INSPECT + CLOSE, 0, 0, close(partialWord), 0, "chunked partial seek refusal wrote persistent");

        // Unavailable storage: the handler refuses before any effect.
        ModeStoreApplet.control = 4;
        expect(0x6A88, INSPECT, 0, 2, a, 0, "chunked unavailable store wrote persistent");
        ModeStoreApplet.control = 0;
        expect(0x6A80, INSPECT, 1, 2, b, 0, "chunked unavailable store retained live handle");
        inspectSession(t, "chunked fresh session after handler refusals");

        // Literal storage vectors independently pin word order, modulo wrap,
        // XOR and the valid neighbors of reserved FFFF.
        byte[] wrap = {0, 1, 4, (byte) 0xFF, 0, 2};
        sendChunks(wrap, "relative seek literal control");
        byte[] literal = expect(0x9000, INSPECT + CLOSE, 0, 0, close(wrap), 0, "relative seek literal close");
        if (!Arrays.equals(literal, new byte[] {0, 3, 0, 2, 4, (byte) 0xFC}))
            throw new AssertionError("relative seek literal fields");
        inspectSession(new byte[] {0, 0}, "zero seek control");
        inspectSession(new byte[] {(byte) 0xFF, (byte) 0xFE}, "reserved seek neighbor control");
    }

    // ----------------------------------------------------------------- public

    // Option A, INS 0x13 only: accepted public chunks are staged; every refused
    // APDU writes 0 B and kills the stream; the result is produced into RAM.
    static void publicStreams() throws Exception {
        reset();
        auth(false); // public methods are admitted without authentication
        byte[] in = chunk(352, 5);
        byte[] a = Arrays.copyOf(in, 192), b = Arrays.copyOfRange(in, 192, 352);
        expect(0x9000, PREVIEW, 0, 2, a, 192, "public accepted first chunk");
        expect(0x9000, PREVIEW, 1, 2, b, 160, "public accepted last chunk");
        expect(0x9000, PREVIEW, 1, 2, b, 0, "public identical duplicate wrote");
        int prepared = ModeStoreApplet.prepareCalls;
        byte[] descriptor = expect(0x9000, PREVIEW + CLOSE, 0, 0, close(in), 0, "public close wrote persistent");
        if (ModeStoreApplet.prepareCalls != prepared + 1) throw new AssertionError("public result not prepared once");
        checkDescriptor(descriptor, 352, 2, "public descriptor");
        if (!Arrays.equals(descriptor, expect(0x9000, PREVIEW + INFO, 0, 0, EMPTY, 0, "public info wrote persistent")))
            throw new AssertionError("public info differs from the close descriptor");
        byte[] result = readAll(PREVIEW, 2, "public read wrote persistent");
        checkResult(descriptor, result, "public read does not match the descriptor");
        checkEnvelope(in, result, "public result bytes");
        if (!Arrays.equals(Arrays.copyOfRange(result, 192, 352), expect(0x9000, PREVIEW + READ, 1, 2, EMPTY, 0, "public read retry wrote persistent")))
            throw new AssertionError("public read retry differs");
        expect(0x9000, PREVIEW + CLOSE_READ, 0, 0, close(result), 0, "public close read wrote persistent");
        expect(0x9000, PREVIEW + CLOSE_READ, 0, 0, close(result), 0, "public close read retry wrote persistent");
        expect(0x6985, PREVIEW + READ, 0, 2, EMPTY, 0, "public read after close read wrote persistent");

        // Bounds: 1472 B upload and 1472 B result.
        byte[] env = chunk(1472, 7);
        for (int i = 0; i < 8; i++) {
            byte[] p = part(env, i);
            expect(0x9000, PREVIEW, i, 8, p, p.length, "public bounded chunk");
        }
        byte[] envDescriptor = expect(0x9000, PREVIEW + CLOSE, 0, 0, close(env), 0, "public bounded close wrote persistent");
        checkDescriptor(envDescriptor, 1472, 8, "public bounded descriptor");
        byte[] envResult = readAll(PREVIEW, 8, "public bounded read wrote persistent");
        checkResult(envDescriptor, envResult, "public bounded read does not match the descriptor");
        checkEnvelope(env, envResult, "public bounded result bytes");
        // A WRITE while the result is pending is refused and kills the result.
        expect(0x6A80, PREVIEW, 0, 2, a, 0, "public write during pending read wrote persistent");
        expect(0x6985, PREVIEW + CLOSE_READ, 0, 0, close(envResult), 0, "public pending read refusal retained live handle");
        expect(0x6700, PREVIEW, 0, 9, part(env, 0), 0, "public oversized declaration wrote persistent");
        // Declared result maximum: exactly 1472 B from a 352 B upload.
        ModeStoreApplet.control = 9;
        publicUpload(in, "public maximum result control");
        byte[] maxDescriptor = expect(0x9000, PREVIEW + CLOSE, 0, 0, close(in), 0, "public maximum result wrote persistent");
        checkDescriptor(maxDescriptor, 1472, 8, "public maximum descriptor");
        checkResult(maxDescriptor, readAll(PREVIEW, 8, "public maximum read wrote persistent"), "public maximum read");
        ModeStoreApplet.control = 0;
        expect(0x9000, PREVIEW + ABORT, 0, 0, EMPTY, 0, "public abort after maximum result");

        // Upload refusals: 0 B, and the stream is dead afterwards.
        publicFirst(a);
        byte[] changed = a.clone();
        changed[7] ^= 1;
        expect(0x6A80, PREVIEW, 0, 2, changed, 0, "public changed duplicate wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public changed duplicate retained live handle");
        expect(0x9000, PREVIEW, 0, 3, part(env, 0), 192, "public order control");
        expect(0x6A80, PREVIEW, 2, 3, part(env, 2), 0, "public out-of-order chunk wrote persistent");
        expect(0x6A80, PREVIEW, 1, 3, part(env, 1), 0, "public order refusal retained live handle");
        expect(0x6700, PREVIEW, 0, 2, Arrays.copyOf(a, 100), 0, "public short middle chunk wrote persistent");
        expect(0x9000, PREVIEW, 0, 3, part(env, 0), 192, "public mid-stream shape control");
        expect(0x6700, PREVIEW, 1, 3, Arrays.copyOf(part(env, 1), 100), 0, "public mid-stream short chunk wrote persistent");
        expect(0x6A80, PREVIEW, 1, 3, part(env, 1), 0, "public short middle refusal left a live stream");
        publicUpload(in, "public close length control");
        byte[] wrongLength = close(in);
        wrongLength[1] ^= 1;
        expect(0x6700, PREVIEW + CLOSE, 0, 0, wrongLength, 0, "public close length wrote persistent");
        expect(0x6985, PREVIEW + CLOSE, 0, 0, close(in), 0, "public close length retained live handle");
        publicUpload(in, "public close digest control");
        byte[] wrongDigest = close(in);
        wrongDigest[20] ^= 1;
        expect(0x6A80, PREVIEW + CLOSE, 0, 0, wrongDigest, 0, "public bad close digest wrote persistent");
        expect(0x6985, PREVIEW + CLOSE, 0, 0, close(in), 0, "public bad digest retained live handle");
        publicFirst(a);
        expect(0x9000, PREVIEW + ABORT, 0, 0, EMPTY, 0, "public abort wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public abort retained live handle");
        publicFirst(a);
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public post-reset retry wrote persistent");
        expect(0x6985, PREVIEW + CLOSE, 0, 0, close(in), 0, "public post-reset close wrote persistent");
        publicFirst(a);
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": public deselect wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public deselect retained live handle");
        publicFirst(a);
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(in), 0, "public foreign method wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public foreign refusal retained live handle");
        publicFirst(a);
        expect(0x6985, INSPECT, 0, 2, Arrays.copyOf(offsets(194), 192), 0, "public foreign write wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, b, 0, "public foreign write retained live handle");

        // Result refusals at CLOSE: prepare failure, invalid totals, producer failure.
        for (int[] c : new int[][] {{5, 0x6A80}, {6, 0x6700}, {7, 0x6700}}) {
            ModeStoreApplet.control = c[0];
            publicUpload(in, "public prepare control " + c[0]);
            expect(c[1], PREVIEW + CLOSE, 0, 0, close(in), 0, "public prepare refusal " + c[0] + " wrote persistent");
            expect(0x6985, PREVIEW + INFO, 0, 0, EMPTY, 0, "public prepare refusal " + c[0] + " retained live handle");
        }
        ModeStoreApplet.control = 0;
        ModeStoreApplet.failProduceAt = 2;
        expect(0x9000, PREVIEW, 0, 3, part(env, 0), 192, "public digest pass failure control");
        expect(0x9000, PREVIEW, 1, 3, part(env, 1), 192, "public digest pass failure control");
        expect(0x9000, PREVIEW, 2, 3, part(env, 2), 192, "public digest pass failure control");
        expect(0x6F00, PREVIEW + CLOSE, 0, 0, close(Arrays.copyOf(env, 576)), 0, "public digest pass failure wrote persistent");
        expect(0x6985, PREVIEW + INFO, 0, 0, EMPTY, 0, "public digest pass failure retained live handle");
        ModeStoreApplet.failProduceAt = 0;
        // The engine was left mid-digest by that refusal; a staged CLOSE must not inherit it.
        publicUpload(in, "public close after digest pass failure control");
        expect(0x9000, PREVIEW + CLOSE, 0, 0, close(in), 0, "public close after digest pass failure");
        expect(0x9000, PREVIEW + ABORT, 0, 0, EMPTY, 0, "public abort after digest control");

        // Read refusals: 0 B, and the result handle is dead afterwards.
        ModeStoreApplet.failProduceAt = 2 + 2;
        publicClosed(in, "public read failure control");
        expect(0x9000, PREVIEW + READ, 0, 2, EMPTY, 0, "public read before failure");
        expect(0x6F00, PREVIEW + READ, 1, 2, EMPTY, 0, "public read failure wrote persistent");
        ModeStoreApplet.failProduceAt = 0;
        expect(0x6985, PREVIEW + READ, 1, 2, EMPTY, 0, "public read failure retained live handle");
        publicClosed(in, "public bad read index control");
        expect(0x6A80, PREVIEW + READ, 2, 2, EMPTY, 0, "public bad read index wrote persistent");
        expect(0x6985, PREVIEW + READ, 0, 2, EMPTY, 0, "public bad read index retained live handle");
        publicClosed(in, "public bad read count control");
        expect(0x6A80, PREVIEW + READ, 0, 3, EMPTY, 0, "public bad read count wrote persistent");
        expect(0x6985, PREVIEW + INFO, 0, 0, EMPTY, 0, "public bad read count retained live handle");
        publicClosed(in, "public bad close read control");
        byte[] r2 = readAll(PREVIEW, 2, "public read before bad close read");
        byte[] badCloseRead = close(r2);
        badCloseRead[9] ^= 1;
        expect(0x6A80, PREVIEW + CLOSE_READ, 0, 0, badCloseRead, 0, "public bad close read wrote persistent");
        expect(0x6985, PREVIEW + READ, 0, 2, EMPTY, 0, "public bad close read retained live handle");

        // A producer that is not deterministic is caught by the host digest check.
        ModeStoreApplet.control = 8;
        ModeStoreApplet.driftAfter = 2;
        byte[] d3 = publicClosed(in, "public drifting producer control");
        byte[] drifted = readAll(PREVIEW, 2, "public drifting read wrote persistent");
        if (Arrays.equals(digest(drifted), Arrays.copyOfRange(d3, 3, 35))) throw new AssertionError("host did not detect a drifting producer");
        ModeStoreApplet.control = 0;
        expect(0x6A80, PREVIEW + CLOSE_READ, 0, 0, close(drifted), 0, "drifting result close read wrote persistent");
    }

    // -------------------------------------------------------------- record transfer

    // INS 0x43 reduces relative seeks in RAM, then reads a circular window
    // directly from the persistent store. Every APDU writes 0 B.
    static void recordStreams() throws Exception {
        reset();
        auth(false);
        byte[] t = offsets(352);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, 352);
        byte[] before = workspace.clone();
        int calls = ModeStoreApplet.chunkCalls;
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer first chunk wrote persistent");
        expect(0x9000, WINDOW, 1, 2, b, 0, "record transfer last chunk wrote persistent");
        byte[] descriptor = expect(0x9000, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer close wrote persistent");
        int total = ModeStoreApplet.windowLength, packets = (total + 191) / 192;
        checkDescriptor(descriptor, total, packets, "record transfer descriptor");
        if (!Arrays.equals(descriptor, expect(0x9000, WINDOW + INFO, 0, 0, EMPTY, 0, "record transfer info wrote persistent")))
            throw new AssertionError("record transfer info differs from the close descriptor");
        byte[] result = readAll(WINDOW, packets, "record transfer read wrote persistent");
        checkResult(descriptor, result, "record transfer read does not match the descriptor");
        checkRecordTransfer(t, result, "record transfer result is not circular storage window");
        if (!Arrays.equals(Arrays.copyOf(result, 192), expect(0x9000, WINDOW + READ, 0, packets, EMPTY, 0, "record transfer read retry wrote persistent")))
            throw new AssertionError("record transfer read retry differs");
        expect(0x9000, WINDOW + CLOSE_READ, 0, 0, close(result), 0, "record transfer close read wrote persistent");
        expect(0x9000, WINDOW + CLOSE_READ, 0, 0, close(result), 0, "record transfer close read retry wrote persistent");
        if (!Arrays.equals(before, workspace)) throw new AssertionError("record transfer session staged the request or the result");
        if (ModeStoreApplet.chunkCalls - calls != 2) throw new AssertionError("record transfer handler did not receive each chunk once");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer close retry wrote persistent");

        // Declared result maximum: the whole 1280 B circular store.
        ModeStoreApplet.control = 9;
        recordUpload(t, "record transfer maximum result control");
        byte[] maxDescriptor = expect(0x9000, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer maximum result wrote persistent");
        checkDescriptor(maxDescriptor, 1280, 7, "record transfer maximum descriptor");
        byte[] maxResult = readAll(WINDOW, 7, "record transfer maximum read wrote persistent");
        checkResult(maxDescriptor, maxResult, "record transfer maximum read");
        checkRecordTransfer(t, maxResult, "record transfer maximum result is not circular storage window");
        ModeStoreApplet.control = 0;
        expect(0x9000, WINDOW + ABORT, 0, 0, EMPTY, 0, "record transfer abort after maximum result");

        // Upload refusals: nothing is staged, so every repeat is refused too.
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer duplicate control");
        expect(0x6A80, WINDOW, 0, 2, a, 0, "record transfer identical duplicate wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer duplicate refusal retained live handle");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer changed duplicate control");
        byte[] changed = a.clone();
        changed[50] ^= 1;
        expect(0x6A80, WINDOW, 0, 2, changed, 0, "record transfer changed duplicate wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer changed duplicate left a live stream");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer changed duplicate retained live handle");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer out-of-order first packet wrote persistent");
        expect(0x6700, WINDOW, 0, 3, a, 0, "record transfer oversized declaration wrote persistent");
        expect(0x6700, WINDOW, 0, 2, Arrays.copyOf(a, 100), 0, "record transfer short middle chunk wrote persistent");
        // Mid-stream shape refusal (index past the declared count), then the
        // valid last chunk: a live stream would accept it.
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer mid-stream shape control");
        expect(0x6700, WINDOW, 2, 2, b, 0, "record transfer index past count wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer shape refusal left a live stream");
        recordUpload(t, "record transfer close digest control");
        byte[] wrongDigest = close(t);
        wrongDigest[30] ^= 1;
        expect(0x6A80, WINDOW + CLOSE, 0, 0, wrongDigest, 0, "record transfer bad close digest wrote persistent");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer bad digest retained live handle");
        recordUpload(t, "record transfer close length control");
        byte[] wrongLength = close(t);
        wrongLength[1] ^= 1;
        expect(0x6700, WINDOW + CLOSE, 0, 0, wrongLength, 0, "record transfer close length wrote persistent");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer close length retained live handle");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer early close control");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer early close wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer early close retained live handle");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer abort control");
        expect(0x9000, WINDOW + ABORT, 0, 0, EMPTY, 0, "record transfer abort wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer abort retained live handle");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer reset control");
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer post-reset close wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer post-reset retry wrote persistent");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer deselect control");
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": record transfer deselect wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer deselect retained live handle");
        expect(0x9000, WINDOW, 0, 2, a, 0, "record transfer foreign control");
        expect(0x6985, PREVIEW + READ, 0, 1, EMPTY, 0, "record transfer foreign method wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer foreign refusal retained live handle");

        // Handler refusals: parser, unavailable store, prepare failure, invalid totals.
        byte[] reservedSeek = t.clone();
        reservedSeek[0] = reservedSeek[1] = (byte) 0xFF;
        expect(0x6A80, WINDOW, 0, 2, Arrays.copyOf(reservedSeek, 192), 0, "record transfer reserved seek refusal wrote persistent");
        expect(0x6A80, WINDOW, 1, 2, b, 0, "record transfer reserved seek refusal retained live handle");
        ModeStoreApplet.control = 4;
        expect(0x6A88, WINDOW, 0, 2, a, 0, "record transfer unavailable store wrote persistent");
        ModeStoreApplet.control = 0;
        byte[] partialWord = Arrays.copyOf(t, t.length - 1);
        recordUpload(partialWord, "record transfer partial seek control");
        expect(0x6A80, WINDOW + CLOSE, 0, 0, close(partialWord), 0, "record transfer partial seek refusal wrote persistent");
        for (int[] c : new int[][] {{5, 0x6A80}, {6, 0x6700}, {7, 0x6700}}) {
            ModeStoreApplet.control = c[0];
            recordUpload(t, "record transfer prepare control " + c[0]);
            expect(c[1], WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer prepare refusal " + c[0] + " wrote persistent");
            expect(0x6985, WINDOW + INFO, 0, 0, EMPTY, 0, "record transfer prepare refusal " + c[0] + " retained live handle");
        }
        ModeStoreApplet.control = 0;
        ModeStoreApplet.failProduceAt = 2;
        recordUpload(t, "record transfer digest pass failure control");
        expect(0x6F00, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer digest pass failure wrote persistent");
        expect(0x6985, WINDOW + INFO, 0, 0, EMPTY, 0, "record transfer digest pass failure retained live handle");
        ModeStoreApplet.failProduceAt = packets + 2;
        recordUpload(t, "record transfer read failure control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer read failure close");
        expect(0x9000, WINDOW + READ, 0, packets, EMPTY, 0, "record transfer read before failure");
        expect(0x6F00, WINDOW + READ, 1, packets, EMPTY, 0, "record transfer read failure wrote persistent");
        ModeStoreApplet.failProduceAt = 0;
        expect(0x6985, WINDOW + READ, 1, packets, EMPTY, 0, "record transfer read failure retained live handle");
        recordUpload(t, "record transfer bad read index control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer bad read index close");
        expect(0x6A80, WINDOW + READ, packets, packets, EMPTY, 0, "record transfer bad read index wrote persistent");
        expect(0x6985, WINDOW + READ, 0, packets, EMPTY, 0, "record transfer bad read index retained live handle");

        // A drifting producer is caught by the host digest check.
        ModeStoreApplet.control = 8;
        ModeStoreApplet.driftAfter = packets;
        recordUpload(t, "record transfer drifting producer control");
        byte[] d3 = expect(0x9000, WINDOW + CLOSE, 0, 0, close(t), 0, "record transfer drifting close");
        byte[] drifted = readAll(WINDOW, packets, "record transfer drifting read wrote persistent");
        if (Arrays.equals(digest(drifted), Arrays.copyOfRange(d3, 3, 35))) throw new AssertionError("host did not detect a drifting record transfer producer");
        ModeStoreApplet.control = 0;
        expect(0x6A80, WINDOW + CLOSE_READ, 0, 0, close(drifted), 0, "record transfer drifting close read wrote persistent");
    }
    // -------------------------------------------------------------- authority

    static void authority() throws Exception {
        reset();
        byte[] leaf = chunk(197, 9);
        byte[] a = Arrays.copyOf(leaf, 192), b = Arrays.copyOfRange(leaf, 192, 197);
        auth(false);
        expect(0x6982, PUT, 0, 2, a, 0, "pre-auth put staged");
        expect(0x6982, PUT + ABORT, 0, 0, EMPTY, 0, "pre-auth put abort");
        auth(true);
        expect(0x9000, PUT, 0, 2, a, 192, "upload accepted first chunk");
        // No unauthenticated APDU of any method can cancel or join the live upload.
        auth(false);
        byte[] in = chunk(352, 5);
        expect(0x6982, PREVIEW, 0, 2, Arrays.copyOf(in, 192), 0, "unauthenticated public write cancelled authenticated upload");
        expect(0x6982, INSPECT, 0, 2, Arrays.copyOf(offsets(194), 192), 0, "unauthenticated chunked write cancelled authenticated upload");
        expect(0x6982, WINDOW + ABORT, 0, 0, EMPTY, 0, "unauthenticated abort cancelled authenticated upload");
        expect(0x6982, PUT + CLOSE, 0, 0, close(leaf), 0, "unauthenticated upload close");
        // Every non-WRITE operation of a foreign method is refused the same way.
        // After each refusal an identical upload duplicate (0 B, 9000) proves the
        // upload is still live; a fresh session would stage 192 B instead.
        int[][] foreign = {{PREVIEW, CLOSE, 0}, {INSPECT, CLOSE, 0}, {WINDOW, CLOSE, 0}, {PREVIEW, INFO, 0}, {WINDOW, INFO, 0},
                {PREVIEW, READ, 2}, {WINDOW, READ, 4}, {PREVIEW, CLOSE_READ, 0}, {WINDOW, CLOSE_READ, 0}};
        String[] foreignNames = {"foreign close", "chunked close", "record transfer close", "foreign info", "record transfer info",
                "foreign read", "record transfer read", "foreign close read", "record transfer close read"};
        for (int i = 0; i < foreign.length; i++) {
            int op = foreign[i][1];
            byte[] data = op == CLOSE || op == CLOSE_READ ? close(in) : EMPTY;
            expect(0x6982, foreign[i][0] + op, 0, foreign[i][2], data, 0,
                    "unauthenticated " + foreignNames[i] + " cancelled authenticated upload");
            auth(true);
            expect(0x9000, PUT, 0, 2, a, 0, "unauthenticated " + foreignNames[i] + " left no live authenticated upload");
            auth(false);
        }
        auth(true);
        expect(0x9000, PUT, 1, 2, b, 5, "upload accepted last chunk");
        byte[] receipt = expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 36, "upload close receipt");
        if (receipt.length != 36 || receipt[0] != 0 || receipt[1] != 0 ||
                ((receipt[2] & 255) << 8 | receipt[3] & 255) != leaf.length ||
                !Arrays.equals(Arrays.copyOfRange(receipt, 4, 36), digest(leaf)))
            throw new AssertionError("page description length/digest");
        expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 0, "upload close retry wrote");
        // F2 in the mode runtime: an authenticated foreign APDU kills the authenticated upload.
        expect(0x9000, PUT, 0, 2, a, 192, "upload foreign control");
        expect(0x6985, PREVIEW, 0, 2, Arrays.copyOf(in, 192), 0, "upload foreign write wrote persistent");
        expect(0x6A80, PUT, 1, 2, b, 0, "upload foreign refusal retained live handle");
        // A finished upload session does not block a public caller.
        auth(false);
        inspectSession(offsets(194), "public session after upload receipt");
        // An authenticated foreign APDU invalidates a public session, with 0 B.
        publicFirst(Arrays.copyOf(in, 192));
        auth(true);
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "authenticated foreign refusal wrote persistent");
        auth(false);
        expect(0x6A80, PREVIEW, 1, 2, Arrays.copyOfRange(in, 192, 352), 0, "authenticated foreign refusal retained public handle");
    }

    // A current applet-side access refusal must invalidate public output and uploads,
    // without giving the same unauthenticated entry a way to cancel issuer work.
    // Every cleanup APDU must request zero persistent stores. Both transport routes run it.
    static void publicInvalidation() throws Exception {
        reset();
        auth(false);
        byte[] input = chunk(352, 5);
        publicFirst(Arrays.copyOf(input, 192));
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "public invalidation wrote persistent");
        expect(0x6A80, PREVIEW, 1, 2, Arrays.copyOfRange(input, 192, 352), 0,
                "public invalidation retained upload");
        publicClosed(input, "fresh public session after invalidation");
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "pending output invalidation wrote persistent");
        expect(0x6985, PREVIEW + READ, 0, 2, EMPTY, 0, "public invalidation retained output");
        expect(0x6985, PREVIEW + CLOSE, 0, 0, close(input), 0, "public invalidation revived CLOSE receipt");

        // Establish an actual STATE_SHORT_CLOSED public receipt. Its immediate
        // retry after invalidation must be the first subsequent stream APDU:
        // an earlier refusal would itself clear retained state and hide a bug.
        expect(0x9000, PUBLIC_RECEIPT, 0, 2, part(input, 0), 192, "public receipt first chunk");
        expect(0x9000, PUBLIC_RECEIPT, 1, 2, part(input, 1), 160, "public receipt last chunk");
        byte[] publicReceipt = expect(0x9000, PUBLIC_RECEIPT + CLOSE, 0, 0, close(input), 36, "public receipt creation");
        byte[] retry = expect(0x9000, PUBLIC_RECEIPT + CLOSE, 0, 0, close(input), 0, "public receipt replay control");
        if (publicReceipt.length != 36 || !Arrays.equals(publicReceipt, retry)
                || !Arrays.equals(Arrays.copyOfRange(publicReceipt, 4, 36), digest(input)))
            throw new AssertionError("public receipt does not describe the uploaded page");
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "public receipt invalidation wrote persistent");
        expect(0x6985, PUBLIC_RECEIPT + CLOSE, 0, 0, close(input), 0, "public invalidation retained short receipt");

        byte[] seeks = offsets(194);
        expect(0x9000, INSPECT, 0, 2, part(seeks, 0), 0, "chunked invalidation control");
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "chunked invalidation wrote persistent");
        expect(0x6A80, INSPECT, 1, 2, part(seeks, 1), 0, "public invalidation retained chunked input");
        inspectSession(seeks, "fresh chunked session after invalidation");

        recordUpload(input, "chunked streamed output invalidation control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(input), 0, "chunked streamed output close");
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "chunked output invalidation wrote persistent");
        expect(0x6985, WINDOW + READ, 0, 4, EMPTY, 0, "public invalidation retained chunked output");

        byte[] page = chunk(197, 9);
        auth(true);
        expect(0x9000, PUT, 0, 2, part(page, 0), 192, "issuer invalidation control");
        auth(false);
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "public invalidation during issuer upload wrote persistent");
        auth(true);
        // A duplicate writes zero; a cancelled session would stage the first 192 bytes again.
        expect(0x9000, PUT, 0, 2, part(page, 0), 0, "public invalidation cancelled issuer upload");
        expect(0x9000, PUT, 1, 2, part(page, 1), 5, "issuer continuation after public invalidation");
        byte[] receipt = expect(0x9000, PUT + CLOSE, 0, 0, close(page), 36, "issuer completion after public invalidation");
        if (receipt.length != 36 || !Arrays.equals(Arrays.copyOfRange(receipt, 4, 36), digest(page)))
            throw new AssertionError("issuer completion digest after public invalidation");
        auth(false);
        expect(0x9000, 0x02, 0, 0, EMPTY, 0, "public invalidation during issuer receipt wrote persistent");
        auth(true);
        expect(0x9000, PUT + CLOSE, 0, 0, close(page), 0, "public invalidation cancelled issuer receipt");
        expect(0x9000, PUT, 0, 2, part(page, 0), 192, "full abort issuer control");
        expect(0x9000, PUT + ABORT, 0, 0, EMPTY, 0, "full abort must remain available");
        expect(0x6A80, PUT, 1, 2, part(page, 1), 0, "full abort retained issuer upload");
    }

    // ----------------------------------------------------------- request bounds

    // The declared request maximum bounds the running total, not only the packet
    // count: 8 x 192 > 1472 (0x13), 6 x 192 > 1024 (0x23), 2 x 192 > 352 (0x43).
    // An in-count upload whose last chunk takes the total one byte past the
    // maximum, or a full chunk past it, is refused 6700 with 0 B before the
    // handler, and the stream is dead; an upload at exactly the maximum is the
    // accepted control.
    static void requestBounds() throws Exception {
        reset();
        auth(false);
        int[][] families = {{PREVIEW, 1472}, {INSPECT, 1024}, {WINDOW, 352}};
        String[] names = {"public", "chunked", "record transfer"};
        for (int f = 0; f < families.length; f++) {
            int family = families[f][0], max = families[f][1], count = (max + 191) / 192;
            String name = names[f];
            for (int total : new int[] {max + 1, count * 192}) {
                byte[] over = family == PREVIEW ? chunk(total, 11) : offsets(total);
                int calls = ModeStoreApplet.chunkCalls;
                for (int i = 0; i < count - 1; i++) {
                    expect(0x9000, family, i, count, part(over, i), family == PREVIEW ? 192 : 0, name + " over-maximum control");
                }
                byte[] last = part(over, count - 1);
                expect(0x6700, family, count - 1, count, last, 0, name + " request over maximum wrote persistent");
                if (family != PREVIEW && ModeStoreApplet.chunkCalls - calls != count - 1)
                    throw new AssertionError(name + " request over maximum reached the handler [" + route + "]");
                // Dead-stream witness, before any CLOSE: the last chunk cut to
                // fit exactly the maximum, at the same expected index. A live
                // stream accepts it with 9000; a dead one refuses it 6A80, 0 B.
                byte[] fit = Arrays.copyOf(last, max - (count - 1) * 192);
                expect(0x6A80, family, count - 1, count, fit, 0, name + " request over maximum left a live stream");
                // CLOSE refuses any incomplete stream, live or dead; it is a
                // 0 B check here, not the liveness witness.
                expect(0x6985, family + CLOSE, 0, 0, close(Arrays.copyOf(over, (count - 1) * 192)), 0,
                        name + " request over maximum retained live handle");
                expect(0x6A80, family, count - 1, count, last, 0, name + " request over maximum retry wrote persistent");
            }
            byte[] exact = family == PREVIEW ? chunk(max, 11) : offsets(max);
            for (int i = 0; i < count; i++) {
                byte[] p = part(exact, i);
                expect(0x9000, family, i, count, p, family == PREVIEW ? p.length : 0, name + " request at maximum control");
            }
            byte[] closed = expect(0x9000, family + CLOSE, 0, 0, close(exact), 0, name + " request at maximum close wrote persistent");
            if (family == INSPECT) {
                checkSummary(closed, exact, "chunked request at maximum summary");
            } else {
                int total = family == PREVIEW ? max : ModeStoreApplet.windowLength;
                checkDescriptor(closed, total, (total + 191) / 192, name + " request at maximum descriptor");
                expect(0x9000, family + ABORT, 0, 0, EMPTY, 0, name + " request at maximum abort");
            }
        }
    }

    // -------------------------------------------------------------- record transfer

    // Direct route: the caller chooses the arrays. A persistent output or caller
    // workspace is refused before any handler callback; RAM spans are accepted.
    static void spanRecordTransfer() throws Exception {
        reset();
        auth(false);
        byte[] t = offsets(194);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, t.length);
        int calls = ModeStoreApplet.chunkCalls;
        ModeStoreApplet.output = 2;
        expect(0x6985, INSPECT, 0, 2, a, 0, "persistent caller workspace admitted on chunk");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.chunkCalls != calls) throw new AssertionError("persistent caller workspace admitted on chunk: handler ran");
        sendChunks(t, "chunked record transfer control");
        int finishes = ModeStoreApplet.finishCalls;
        ModeStoreApplet.output = 1;
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "persistent response admitted on chunked close");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.finishCalls != finishes) throw new AssertionError("persistent response admitted on chunked close: handler ran");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked record transfer refusal retained live handle");
        // The caller-workspace half of the same CLOSE record transfer: the handler
        // scratch passed to Finish must be RAM as well.
        sendChunks(t, "chunked close workspace control");
        finishes = ModeStoreApplet.finishCalls;
        ModeStoreApplet.output = 2;
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "persistent caller workspace admitted on chunked close");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.finishCalls != finishes) throw new AssertionError("persistent caller workspace admitted on chunked close: handler ran");
        expect(0x6985, INSPECT + CLOSE, 0, 0, close(t), 0, "chunked close workspace refusal retained live handle");
        inspectSession(t, "RAM caller workspace chunked close control");
        sendChunks(t, "transient chunked response control");
        ModeStoreApplet.output = 3;
        checkSummary(expect(0x9000, INSPECT + CLOSE, 0, 0, close(t), 0, "transient chunked response wrote persistent"), t,
                "transient chunked response");
        ModeStoreApplet.output = 0;

        byte[] in = chunk(352, 5);
        int packets = 2;
        for (int span : new int[] {1, 2}) {
            String kind = span == 1 ? "persistent response" : "persistent caller workspace";
            publicUpload(in, kind + " public control");
            int prepared = ModeStoreApplet.prepareCalls;
            ModeStoreApplet.output = span;
            expect(0x6985, PREVIEW + CLOSE, 0, 0, close(in), 0, kind + " admitted on public close");
            ModeStoreApplet.output = 0;
            if (ModeStoreApplet.prepareCalls != prepared) throw new AssertionError(kind + " admitted on public close: handler ran");
            expect(0x6985, PREVIEW + CLOSE, 0, 0, close(in), 0, kind + " public refusal retained live handle");
        }
        publicClosed(in, "persistent read span control");
        int produced = ModeStoreApplet.produceCalls;
        ModeStoreApplet.output = 1;
        expect(0x6985, PREVIEW + READ, 0, packets, EMPTY, 0, "persistent read span admitted");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.produceCalls != produced) throw new AssertionError("persistent read span admitted: handler ran");
        expect(0x6985, PREVIEW + READ, 0, packets, EMPTY, 0, "persistent read refusal retained live handle");
        // The caller-workspace half of READ record transfer: the producer scratch must be RAM.
        publicClosed(in, "public read workspace control");
        produced = ModeStoreApplet.produceCalls;
        ModeStoreApplet.output = 2;
        expect(0x6985, PREVIEW + READ, 0, packets, EMPTY, 0, "persistent caller workspace admitted on public read");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.produceCalls != produced) throw new AssertionError("persistent caller workspace admitted on public read: handler ran");
        expect(0x6985, PREVIEW + READ, 0, packets, EMPTY, 0, "public read workspace refusal retained live handle");
        byte[] ramRead = publicClosed(in, "RAM caller workspace public read control");
        checkResult(ramRead, readAll(PREVIEW, packets, "RAM caller workspace public read wrote persistent"), "RAM caller workspace public read");
        expect(0x9000, PREVIEW + ABORT, 0, 0, EMPTY, 0, "RAM caller workspace public read abort");
        publicClosed(in, "persistent descriptor span control");
        ModeStoreApplet.output = 1;
        expect(0x6985, PREVIEW + INFO, 0, 0, EMPTY, 0, "persistent descriptor span admitted");
        ModeStoreApplet.output = 0;
        expect(0x6985, PREVIEW + INFO, 0, 0, EMPTY, 0, "persistent descriptor refusal retained live handle");
        // Chunked record transfer result: the same record transfer at CLOSE and READ.
        byte[] adm = offsets(352);
        recordUpload(adm, "chunked result record transfer control");
        int preparedAdm = ModeStoreApplet.prepareCalls;
        ModeStoreApplet.output = 1;
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(adm), 0, "persistent response admitted on record transfer close");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.prepareCalls != preparedAdm) throw new AssertionError("persistent response admitted on record transfer close: handler ran");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(adm), 0, "record transfer close refusal retained live handle");
        int admPackets = (ModeStoreApplet.windowLength + 191) / 192;
        recordUpload(adm, "chunked read record transfer control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(adm), 0, "chunked read record transfer close");
        int producedAdm = ModeStoreApplet.produceCalls;
        ModeStoreApplet.output = 1;
        expect(0x6985, WINDOW + READ, 1, admPackets, EMPTY, 0, "persistent read span admitted on record transfer");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.produceCalls != producedAdm) throw new AssertionError("persistent read span admitted on record transfer: handler ran");
        expect(0x6985, WINDOW + READ, 1, admPackets, EMPTY, 0, "record transfer read refusal retained live handle");
        // Caller-workspace half at the record transfer CLOSE (Prepare) and READ (Produce).
        recordUpload(adm, "record transfer close workspace control");
        preparedAdm = ModeStoreApplet.prepareCalls;
        ModeStoreApplet.output = 2;
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(adm), 0, "persistent caller workspace admitted on record transfer close");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.prepareCalls != preparedAdm) throw new AssertionError("persistent caller workspace admitted on record transfer close: handler ran");
        expect(0x6985, WINDOW + CLOSE, 0, 0, close(adm), 0, "record transfer close workspace refusal retained live handle");
        recordUpload(adm, "record transfer read workspace control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(adm), 0, "record transfer read workspace close");
        producedAdm = ModeStoreApplet.produceCalls;
        ModeStoreApplet.output = 2;
        expect(0x6985, WINDOW + READ, 0, admPackets, EMPTY, 0, "persistent caller workspace admitted on record transfer read");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.produceCalls != producedAdm) throw new AssertionError("persistent caller workspace admitted on record transfer read: handler ran");
        expect(0x6985, WINDOW + READ, 0, admPackets, EMPTY, 0, "record transfer read workspace refusal retained live handle");
        recordUpload(adm, "RAM caller workspace record transfer read control");
        expect(0x9000, WINDOW + CLOSE, 0, 0, close(adm), 0, "RAM caller workspace record transfer close wrote persistent");
        checkRecordTransfer(adm, readAll(WINDOW, admPackets, "RAM caller workspace record transfer read wrote persistent"), "RAM caller workspace record transfer result");
        expect(0x9000, WINDOW + ABORT, 0, 0, EMPTY, 0, "RAM caller workspace record transfer abort");
        // Transient response span: the whole record transfer flow is accepted.
        ModeStoreApplet.output = 3;
        recordUpload(adm, "transient record transfer response control");
        byte[] admD = expect(0x9000, WINDOW + CLOSE, 0, 0, close(adm), 0, "transient record transfer close wrote persistent");
        checkRecordTransfer(adm, readAll(WINDOW, admPackets, "transient record transfer read wrote persistent"), "transient record transfer result");
        ModeStoreApplet.output = 0;
        checkDescriptor(admD, ModeStoreApplet.windowLength, admPackets, "transient record transfer descriptor");
        expect(0x9000, WINDOW + ABORT, 0, 0, EMPTY, 0, "record transfer abort after transient control");
        // F1 in the mode runtime: a persistent upload response is refused before the handler.
        byte[] leaf = chunk(197, 9);
        auth(true);
        expect(0x9000, PUT, 0, 2, Arrays.copyOf(leaf, 192), 192, "upload record transfer control");
        expect(0x9000, PUT, 1, 2, Arrays.copyOfRange(leaf, 192, 197), 5, "upload record transfer tail");
        int staged = ModeStoreApplet.stagedCalls;
        ModeStoreApplet.output = 1;
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "persistent response admitted on upload close");
        ModeStoreApplet.output = 0;
        if (ModeStoreApplet.stagedCalls != staged) throw new AssertionError("persistent response admitted on upload close: handler ran");
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "upload record transfer refusal retained live handle");
        auth(false);
        // Transient response span: the whole public flow is accepted.
        ModeStoreApplet.output = 3;
        byte[] d = publicClosed(in, "transient public response control");
        checkResult(d, readAll(PREVIEW, packets, "transient public read wrote persistent"), "transient public read");
        ModeStoreApplet.output = 0;
    }

    // ------------------------------------------------------- runtime refusals

    // Installation-configured runtimes: begin refuses a streamed result for an authenticated
    // method, an unknown mode and a missing request stream before any effect; a
    // valid chunked call is the accepted control.
    static ModeStoreStreamEndpoint configured(Object session, byte mode, boolean request, boolean response) throws Exception {
        byte direction = (byte) ((request ? 2 : 0) | (response ? 1 : 0));
        short width = response ? (short) -1 : (short) 6;
        return new ModeStoreBoundedStreamRuntime((byte[]) field(session, "workspace"),
                (byte[]) field(session, "digestScratch"), (short[]) field(session, "scalars"),
                (Object[]) field(session, "handlerSlot"), ModeStoreApplet.installed.logic,
                ModeStoreApplet.installed.logic, new byte[]{direction, direction},
                new short[]{64, 32, 64, 32, width, 64, 32, 64, 32, width}, new byte[]{mode, mode});
    }

    static void runtimeRefusals(Object session) throws Exception {
        reset();
        ModeStoreStreamEndpoint endpoint = (ModeStoreStreamEndpoint) session;
        byte[] io = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        installedModeCopy(session, io);
        Object[][] cases = {
            {"chunked method without request stream admitted", ModeStoreStreamEndpoint.MODE_CHUNKED, false, true},
            {"authenticated streamed result admitted", ModeStoreStreamEndpoint.MODE_AUTHENTICATED, true, true},
            {"unknown stream mode admitted", (byte) 3, true, false},
            {"public method without request stream admitted", ModeStoreStreamEndpoint.MODE_PUBLIC_INVALIDATE, false, true},
        };
        for (Object[] c : cases) {
            String label = (String) c[0];
            boolean request = (Boolean) c[2], response = (Boolean) c[3];
            endpoint = configured(session, (Byte) c[1], request, response);
            NvmLedger.reset();
            try {
                endpoint.dispatch((byte) 2, ModeStoreStreamEndpoint.OP_WRITE_OR_INVOKE,
                        (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                        io, (short) 0, (short) 255, true);
                throw new AssertionError(label);
            } catch (ModeStoreStreamEndpoint.StreamStatusWordException e) {
                if (e.getStatusWord() != (short) 0x6A84) throw new AssertionError(label + ": " + Integer.toHexString(e.getStatusWord() & 65535));
            }
            if (NvmLedger.persistent != 0) throw new AssertionError(label + ": wrote persistent");
        }
        endpoint = configured(session, ModeStoreStreamEndpoint.MODE_CHUNKED, true, false);
        NvmLedger.reset();
        Arrays.fill(io, (byte) 0);
        io[1] = 1; // One relative seek of 1, then 0.
        try {
            endpoint.dispatch((byte) 2, ModeStoreStreamEndpoint.OP_WRITE_OR_INVOKE,
                    (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                    io, (short) 0, (short) 255, false);
        } catch (ModeStoreStreamEndpoint.StreamStatusWordException e) {
            throw new AssertionError("chunked runtime control refused: " + Integer.toHexString(e.getStatusWord() & 65535));
        }
        if (NvmLedger.persistent != 0) throw new AssertionError("chunked runtime control wrote persistent");
        endpoint.abort(ModeStoreStreamEndpoint.ABORT_EXPLICIT);
    }

    // A caller cannot mutate installed authentication or request bounds through
    // the original configuration arrays. The refusal and accepted write have
    // separate ledger assertions; installation stores are excluded explicitly.
    static void installedModeCopy(Object session, byte[] io) throws Exception {
        byte[] directions = {2};
        short[] limits = {64, 32, 0, 0, 6};
        byte[] modes = {ModeStoreStreamEndpoint.MODE_AUTHENTICATED};
        ModeStoreStreamEndpoint endpoint = new ModeStoreBoundedStreamRuntime(
                (byte[]) field(session, "workspace"), (byte[]) field(session, "digestScratch"),
                (short[]) field(session, "scalars"), (Object[]) field(session, "handlerSlot"),
                ModeStoreApplet.installed.logic, ModeStoreApplet.installed.logic, directions, limits, modes);
        directions[0] = 0;
        Arrays.fill(limits, (short) 0);
        modes[0] = ModeStoreStreamEndpoint.MODE_CHUNKED;
        short[] before = ((short[]) field(session, "scalars")).clone();
        byte[] bulk = ((byte[]) field(session, "workspace")).clone();
        NvmLedger.reset();
        try {
            endpoint.dispatch((byte) 1, ModeStoreStreamEndpoint.OP_WRITE_OR_INVOKE,
                    (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                    io, (short) 0, (short) 255, false);
            throw new AssertionError("configuration mutation bypassed authentication");
        } catch (ModeStoreStreamEndpoint.StreamStatusWordException failure) {
            if (failure.getStatusWord() != (short) 0x6982) throw new AssertionError("configuration mutation changed refusal");
        }
        if (NvmLedger.persistent != 0 || !Arrays.equals(before, (short[]) field(session, "scalars")) ||
                !Arrays.equals(bulk, (byte[]) field(session, "workspace"))) throw new AssertionError("configuration refusal changed session");
        NvmLedger.reset();
        endpoint.dispatch((byte) 1, ModeStoreStreamEndpoint.OP_WRITE_OR_INVOKE,
                (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                io, (short) 0, (short) 255, true);
        if (NvmLedger.persistent != 4) throw new AssertionError("configuration mutation changed valid upload");
        endpoint.abort(ModeStoreStreamEndpoint.ABORT_EXPLICIT);
    }

    // ---------------------------------------------------------------- helpers

    static void reset() {
        ModeStoreApplet.control = 0;
        ModeStoreApplet.failProduceAt = 0;
        ModeStoreApplet.output = 0;
        expectAny(INSPECT + ABORT);
    }

    static void expectAny(int ins) {
        auth(true);
        try {
            send(ins, 0, 0, EMPTY);
        } catch (ISOException e) {
            throw new AssertionError("abort before scenario: " + Integer.toHexString(e.getReason() & 0xFFFF));
        }
    }

    static void inspectSession(byte[] t, String label) throws Exception {
        sendChunks(t, label);
        checkSummary(expect(0x9000, INSPECT + CLOSE, 0, 0, close(t), 0, label + " close wrote persistent"), t, label);
    }

    static void sendChunks(byte[] t, String label) {
        int count = (t.length + 191) / 192;
        for (int i = 0; i < count; i++) expect(0x9000, INSPECT, i, count, part(t, i), 0, label);
    }

    static void publicFirst(byte[] a) {
        expect(0x9000, PREVIEW, 0, 2, a, 192, "public first chunk control");
    }

    static void publicUpload(byte[] in, String label) {
        expect(0x9000, PREVIEW, 0, 2, Arrays.copyOf(in, 192), 192, label);
        expect(0x9000, PREVIEW, 1, 2, Arrays.copyOfRange(in, 192, 352), 160, label);
    }

    static byte[] publicClosed(byte[] in, String label) {
        publicUpload(in, label);
        byte[] d = expect(0x9000, PREVIEW + CLOSE, 0, 0, close(in), 0, label + " close");
        checkDescriptor(d, 352, 2, label);
        return d;
    }

    static void recordUpload(byte[] t, String label) {
        expect(0x9000, WINDOW, 0, 2, Arrays.copyOf(t, 192), 0, label);
        expect(0x9000, WINDOW, 1, 2, Arrays.copyOfRange(t, 192, t.length), 0, label);
    }

    // Page preview: reversal of the staged request, independently indexed.
    static void checkEnvelope(byte[] in, byte[] result, String label) {
        for (int at = 0; at < result.length; at++) {
            if (result[at] != (byte) (in[in.length - 1 - at % in.length])) throw new AssertionError(label);
        }
    }

    // Independent oracle: use host int arithmetic and the installation formula,
    // never the applet's reducer state or its stored array as the expectation.
    static int cursor(byte[] offsets) {
        int total = 0;
        for (int i = 0; i < offsets.length; i += 2) {
            total += ((offsets[i] & 255) << 8) | (offsets[i + 1] & 255);
        }
        return total % 1280;
    }

    static void checkRecordTransfer(byte[] offsets, byte[] result, String label) {
        int start = cursor(offsets);
        for (int i = 0; i < result.length; i++) {
            int at = (start + i) % 1280;
            if (result[i] != (byte) (at / 16 + at % 16)) throw new AssertionError(label + ": window byte " + i);
        }
    }

    static byte[] readAll(int family, int packets, String label) {
        byte[] all = new byte[0];
        for (int i = 0; i < packets; i++) all = cat(all, expect(0x9000, family + READ, i, packets, EMPTY, 0, label));
        return all;
    }

    static void checkDescriptor(byte[] d, int total, int packets, String label) {
        if (d.length != 35 || (d[0] & 255) != packets || (((d[1] & 255) << 8) | (d[2] & 255)) != total)
            throw new AssertionError(label + ": descriptor " + d.length + "/" + (d.length > 0 ? d[0] & 255 : -1));
    }

    static void checkResult(byte[] descriptor, byte[] result, String label) {
        int total = ((descriptor[1] & 255) << 8) | (descriptor[2] & 255);
        if (result.length != total || !Arrays.equals(digest(result), Arrays.copyOfRange(descriptor, 3, 35)))
            throw new AssertionError(label);
    }

    static void checkSummary(byte[] response, byte[] offsets, String label) {
        if (response.length != 6) throw new AssertionError(label + ": response length " + response.length);
        int xor = 0;
        for (int i = 0; i < offsets.length; i += 2) xor ^= ((offsets[i] & 255) << 8) | (offsets[i + 1] & 255);
        int[] expected = {offsets.length / 2, cursor(offsets), xor};
        for (int i = 0; i < 3; i++) {
            int value = ((response[i * 2] & 255) << 8) | (response[i * 2 + 1] & 255);
            if (value != expected[i]) throw new AssertionError(label + ": summary field " + i);
        }
    }

    static void auth(boolean value) {
        ModeStoreApplet.authenticated = value;
    }

    static byte[] expect(int sw, int ins, int p1, int p2, byte[] data, int persistent, String label) {
        NvmLedger.reset();
        byte[] out = EMPTY;
        int got;
        try {
            out = send(ins, p1, p2, data);
            got = 0x9000;
        } catch (ISOException e) {
            got = e.getReason() & 65535;
        }
        if (got != sw)
            throw new AssertionError(label + " [" + route + "]: status " + Integer.toHexString(got) + " expected " + Integer.toHexString(sw));
        if (NvmLedger.persistent != persistent)
            throw new AssertionError(label + " [" + route + "]: persistent stores " + NvmLedger.persistent + " expected " + persistent);
        return out;
    }

    static byte[] offsets(int total) {
        return chunk(total, 3); // Raw u16 relative seeks, with no tag or length prefix.
    }

    static byte[] part(byte[] data, int index) {
        return Arrays.copyOfRange(data, index * 192, Math.min(data.length, (index + 1) * 192));
    }

    static byte[] chunk(int n, int seed) {
        byte[] r = new byte[n];
        for (int i = 0; i < n; i++) r[i] = (byte) (seed * 31 + i * 7);
        return r;
    }

    static byte[] cat(byte[] x, byte[] y) {
        byte[] r = Arrays.copyOf(x, x.length + y.length);
        System.arraycopy(y, 0, r, x.length, y.length);
        return r;
    }

    static byte[] send(int ins, int p1, int p2, byte[] data) {
        byte[] a = new byte[data.length == 0 ? 4 : data.length + 5];
        a[0] = (byte) 0xB0;
        a[1] = (byte) ins;
        a[2] = (byte) p1;
        a[3] = (byte) p2;
        if (data.length > 0) {
            a[4] = (byte) data.length;
            System.arraycopy(data, 0, a, 5, data.length);
        }
        byte[] r = simulator.transmitCommand(a);
        int n = r.length;
        short sw = (short) (((r[n - 2] & 255) << 8) | (r[n - 1] & 255));
        if (sw != (short) 0x9000) ISOException.throwIt(sw);
        return Arrays.copyOf(r, n - 2);
    }

    static byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] close(byte[] data) {
        byte[] r = new byte[34];
        r[0] = (byte) (data.length >> 8);
        r[1] = (byte) data.length;
        System.arraycopy(digest(data), 0, r, 2, 32);
        return r;
    }

    static Object field(Object x, String n) throws Exception {
        Class<?> c = x.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(n);
                f.setAccessible(true);
                return f.get(x);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(n);
    }

    public static class EmptyApplet extends Applet {
        public static void install(byte[] b, short o, byte l) {
            new EmptyApplet().register();
        }

        public void process(APDU a) {
        }
    }
}
