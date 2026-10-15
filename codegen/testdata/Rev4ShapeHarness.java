package io.jcrpc.rev4shape.server;

import javacard.framework.*;
import javacard.security.Signature;
import com.licel.jcardsim.base.*;
import java.lang.reflect.*;
import java.util.*;
import java.security.MessageDigest;

/**
 * Drives Simulator.transmitCommand -> Rev4ShapeApplet.process -> generated
 * processIfStream (adapter route) or dispatchStreamTo (direct route) ->
 * generated runtime dispatch. Every APDU asserts its status word and its
 * logical persistent store count; each refusal is followed by a check that the
 * refused stream is dead and by a nearby accepted control.
 */
public class Rev4ShapeHarness {
    static Simulator simulator;
    static AID aid, other;
    static byte[] workspace;
    static String route;
    static final byte[] EMPTY = new byte[0];

    // INS families.
    static final int ENV = 0x10, SIGN = 0x20, PUT = 0x58, ADM = 0x70;
    static final int WRITE = 0, CLOSE = 1, INFO = 2, READ = 3, CLOSE_READ = 4, ABORT = 5;

    public static void main(String[] args) throws Exception {
        simulator = new Simulator();
        aid = new AID(new byte[] {(byte) 0xF0, 0, 0, 1, 4, 1}, (short) 0, (byte) 6);
        other = new AID(new byte[] {(byte) 0xF0, 0, 0, 1, 4, 2}, (short) 0, (byte) 6);
        simulator.installApplet(aid, Rev4ShapeApplet.class);
        simulator.installApplet(other, EmptyApplet.class);
        simulator.selectApplet(aid);
        Object session = field(Rev4ShapeApplet.installed.logic, "streamSession");
        workspace = (byte[]) field(session, "workspace");
        // Ledger classification control: the workspace is persistent, a transient array is not.
        NvmLedger.reset();
        NvmLedger.store(workspace);
        NvmLedger.store(JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET));
        if (NvmLedger.persistent != 1 || NvmLedger.transientStores != 1) throw new AssertionError("ledger classification control");
        String only = args.length > 0 ? args[0] : "all";
        for (boolean direct : new boolean[] {false, true}) {
            Rev4ShapeApplet.direct = direct;
            route = direct ? "direct" : "adapter";
            if (only.equals("all") || only.equals("chunked")) chunked();
            if (only.equals("all") || only.equals("public")) publicStreams();
            if (only.equals("all") || only.equals("admission")) admissionStreams();
            if (only.equals("all") || only.equals("authority")) authority();
            if (only.equals("all") || only.equals("bounds")) requestBounds();
            if (direct && (only.equals("all") || only.equals("spans"))) spanAdmission();
        }
        runtimeRefusals(session);
        System.out.println("stream modes: chunked signature, chunked admission, public envelope, authority and span controls green on adapter and direct routes");
    }

    // ---------------------------------------------------------------- chunked

    static void chunked() throws Exception {
        reset();
        auth(false); // chunked methods are public: no authentication is required
        byte[] t = transcript(194);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, t.length);
        byte[] before = workspace.clone();
        int calls = Rev4ShapeApplet.chunkCalls;
        Rev4ShapeApplet.maxChunk = 0;
        Rev4ShapeApplet.chunkFromPersistent = false;
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked first chunk wrote persistent");
        expect(0x9000, SIGN, 1, 2, b, 0, "chunked last chunk wrote persistent");
        byte[] sig = expect(0x9000, SIGN + CLOSE, 0, 0, close(t), 0, "chunked close wrote persistent");
        if (sig.length != 73) throw new AssertionError("chunked response is not one 73 B response: " + sig.length);
        verify(sig, t, "chunked signature does not cover the whole transcript");
        if (!Arrays.equals(before, workspace)) throw new AssertionError("chunked session staged the request");
        if (Rev4ShapeApplet.chunkCalls - calls != 2 || Rev4ShapeApplet.maxChunk != 192)
            throw new AssertionError("chunked handler did not receive each chunk once");
        if (Rev4ShapeApplet.chunkFromPersistent) throw new AssertionError("chunk delivered from persistent memory");
        // No receipt is retained: a CLOSE retry finds no session.
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked close retry wrote persistent");

        // Declared bound: 2048 B in eleven chunks, still 0 B persistent on every APDU.
        byte[] max = transcript(2048);
        before = workspace.clone();
        calls = Rev4ShapeApplet.chunkCalls;
        for (int i = 0; i < 11; i++) {
            expect(0x9000, SIGN, i, 11, part(max, i), 0, "chunked bounded chunk wrote persistent");
        }
        verify(expect(0x9000, SIGN + CLOSE, 0, 0, close(max), 0, "chunked bounded close wrote persistent"), max,
                "chunked bounded signature");
        if (!Arrays.equals(before, workspace) || Rev4ShapeApplet.chunkCalls - calls != 11)
            throw new AssertionError("chunked bounded session staged the request");
        expect(0x6700, SIGN, 0, 12, a, 0, "chunked oversized declaration wrote persistent");

        // Chunk order: a skipped index is refused and kills the stream.
        byte[] t3 = transcript(400);
        expect(0x9000, SIGN, 0, 3, part(t3, 0), 0, "chunked order control");
        expect(0x6A80, SIGN, 2, 3, part(t3, 2), 0, "chunked out-of-order chunk wrote persistent");
        expect(0x6A80, SIGN, 1, 3, part(t3, 1), 0, "chunked retry after order refusal wrote persistent");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t3), 0, "chunked order refusal retained live handle");
        signSession(t3, "chunked fresh session after order refusal");

        // Duplicates: nothing is staged, so any repeat is refused, changed or not.
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked duplicate control");
        byte[] changed = a.clone();
        changed[100] ^= 1;
        expect(0x6A80, SIGN, 0, 2, changed, 0, "chunked changed duplicate wrote persistent");
        // The next chunk at the stream's expected index: a live stream accepts it.
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked changed duplicate left a live stream");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked changed duplicate retained live handle");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked identical duplicate control");
        expect(0x6A80, SIGN, 0, 2, a, 0, "chunked identical duplicate wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked identical duplicate retained live handle");

        // Invalid lengths and close declarations.
        expect(0x6700, SIGN, 0, 2, Arrays.copyOf(a, 100), 0, "chunked short middle chunk wrote persistent");
        // Mid-stream shape refusal: the valid chunk at the same index must find
        // a dead stream (6A80); a live stream would accept it with 9000.
        expect(0x9000, SIGN, 0, 3, part(t3, 0), 0, "chunked mid-stream shape control");
        expect(0x6700, SIGN, 1, 3, Arrays.copyOf(part(t3, 1), 100), 0, "chunked mid-stream short chunk wrote persistent");
        expect(0x6A80, SIGN, 1, 3, part(t3, 1), 0, "chunked short middle refusal left a live stream");
        signSession(t3, "chunked fresh session after shape refusal");
        sendChunks(t, "chunked close length control");
        byte[] wrongLength = close(t);
        wrongLength[1] ^= 1;
        expect(0x6700, SIGN + CLOSE, 0, 0, wrongLength, 0, "chunked close length wrote persistent");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked close length refusal retained live handle");
        sendChunks(t, "chunked close digest control");
        byte[] wrongDigest = close(t);
        wrongDigest[33] ^= 1;
        expect(0x6A80, SIGN + CLOSE, 0, 0, wrongDigest, 0, "chunked bad close digest wrote persistent");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked bad digest retained live handle");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked early close control");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked early close wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked early close retained live handle");
        sendChunks(t, "chunked short close control");
        expect(0x6700, SIGN + CLOSE, 0, 0, Arrays.copyOf(close(t), 33), 0, "chunked short close wrote persistent");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked short close retained live handle");

        // Abort, reset and deselect: 0 B and a dead stream; a fresh session works.
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked abort control");
        expect(0x9000, SIGN + ABORT, 0, 0, EMPTY, 0, "chunked abort wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked abort retained live handle");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked reset control");
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked post-reset close wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked post-reset retry wrote persistent");
        signSession(t, "chunked fresh session after reset");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked deselect control");
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": chunked deselect wrote persistent");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked deselect retained live handle");

        // Foreign method: refused with 0 B and the chunked stream is dead.
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked foreign control");
        auth(true);
        expect(0x6985, PUT, 0, 1, b, 0, "chunked foreign method wrote persistent");
        auth(false);
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked foreign refusal retained live handle");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked foreign read control");
        expect(0x6985, ADM + READ, 0, 1, EMPTY, 0, "chunked foreign read wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked foreign read retained live handle");

        // Handler failures: parser, mid-stream, finish after output, bad length.
        byte[] badTag = t.clone();
        badTag[0] = 0x55;
        expect(0x6A80, SIGN, 0, 2, Arrays.copyOf(badTag, 192), 0, "chunked parser refusal wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked parser refusal retained live handle");
        Rev4ShapeApplet.control = 3;
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked handler failure control");
        expect(0x6F00, SIGN, 1, 2, b, 0, "chunked handler chunk failure wrote persistent");
        // The failed chunk again, with the handler healthy: a live stream accepts it.
        Rev4ShapeApplet.control = 0;
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked handler chunk failure left a live stream");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked handler failure retained live handle");
        Rev4ShapeApplet.control = 1;
        sendChunks(t, "chunked finish failure control");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked finish failure wrote persistent");
        if (NvmLedger.apduStores + NvmLedger.transientStores < 73) throw new AssertionError("failing finish did not write its output");
        Rev4ShapeApplet.control = 2;
        sendChunks(t, "chunked invalid length control");
        expect(0x6700, SIGN + CLOSE, 0, 0, close(t), 0, "chunked invalid result length wrote persistent");
        Rev4ShapeApplet.control = 0;
        byte[] lying = t.clone();
        lying[2] ^= 1; // header body length no longer matches the transcript
        sendChunks(lying, "chunked transcript length control");
        expect(0x6A80, SIGN + CLOSE, 0, 0, close(lying), 0, "chunked transcript length refusal wrote persistent");

        // Missing signing authority: the handler refuses before any effect.
        Rev4ShapeApplet.control = 4;
        expect(0x6A88, SIGN, 0, 2, a, 0, "chunked missing signing key wrote persistent");
        Rev4ShapeApplet.control = 0;
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked missing key retained live handle");
        signSession(t, "chunked fresh session after handler refusals");
    }

    // ----------------------------------------------------------------- public

    // Option A, INS 0x10 only: accepted public chunks are staged; every refused
    // APDU writes 0 B and kills the stream; the result is produced into RAM.
    static void publicStreams() throws Exception {
        reset();
        auth(false); // public methods are admitted without authentication
        byte[] in = chunk(320, 5);
        byte[] a = Arrays.copyOf(in, 192), b = Arrays.copyOfRange(in, 192, 320);
        expect(0x9000, ENV, 0, 2, a, 192, "public accepted first chunk");
        expect(0x9000, ENV, 1, 2, b, 128, "public accepted last chunk");
        expect(0x9000, ENV, 1, 2, b, 0, "public identical duplicate wrote");
        int prepared = Rev4ShapeApplet.prepareCalls;
        byte[] descriptor = expect(0x9000, ENV + CLOSE, 0, 0, close(in), 0, "public close wrote persistent");
        if (Rev4ShapeApplet.prepareCalls != prepared + 1) throw new AssertionError("public result not prepared once");
        checkDescriptor(descriptor, 320, 2, "public descriptor");
        if (!Arrays.equals(descriptor, expect(0x9000, ENV + INFO, 0, 0, EMPTY, 0, "public info wrote persistent")))
            throw new AssertionError("public info differs from the close descriptor");
        byte[] result = readAll(ENV, 2, "public read wrote persistent");
        checkResult(descriptor, result, "public read does not match the descriptor");
        checkEnvelope(in, result, "public result bytes");
        if (!Arrays.equals(Arrays.copyOfRange(result, 192, 320), expect(0x9000, ENV + READ, 1, 2, EMPTY, 0, "public read retry wrote persistent")))
            throw new AssertionError("public read retry differs");
        expect(0x9000, ENV + CLOSE_READ, 0, 0, close(result), 0, "public close read wrote persistent");
        expect(0x9000, ENV + CLOSE_READ, 0, 0, close(result), 0, "public close read retry wrote persistent");
        expect(0x6985, ENV + READ, 0, 2, EMPTY, 0, "public read after close read wrote persistent");

        // Bounds: 1792 B upload and 1792 B result.
        byte[] env = chunk(1792, 7);
        for (int i = 0; i < 10; i++) {
            byte[] p = part(env, i);
            expect(0x9000, ENV, i, 10, p, p.length, "public bounded chunk");
        }
        byte[] envDescriptor = expect(0x9000, ENV + CLOSE, 0, 0, close(env), 0, "public bounded close wrote persistent");
        checkDescriptor(envDescriptor, 1792, 10, "public bounded descriptor");
        byte[] envResult = readAll(ENV, 10, "public bounded read wrote persistent");
        checkResult(envDescriptor, envResult, "public bounded read does not match the descriptor");
        checkEnvelope(env, envResult, "public bounded result bytes");
        // A WRITE while the result is pending is refused and kills the result.
        expect(0x6A80, ENV, 0, 2, a, 0, "public write during pending read wrote persistent");
        expect(0x6985, ENV + CLOSE_READ, 0, 0, close(envResult), 0, "public pending read refusal retained live handle");
        expect(0x6700, ENV, 0, 11, part(env, 0), 0, "public oversized declaration wrote persistent");
        // Declared result maximum: exactly 1792 B from a 320 B upload.
        Rev4ShapeApplet.control = 9;
        publicUpload(in, "public maximum result control");
        byte[] maxDescriptor = expect(0x9000, ENV + CLOSE, 0, 0, close(in), 0, "public maximum result wrote persistent");
        checkDescriptor(maxDescriptor, 1792, 10, "public maximum descriptor");
        checkResult(maxDescriptor, readAll(ENV, 10, "public maximum read wrote persistent"), "public maximum read");
        Rev4ShapeApplet.control = 0;
        expect(0x9000, ENV + ABORT, 0, 0, EMPTY, 0, "public abort after maximum result");

        // Upload refusals: 0 B, and the stream is dead afterwards.
        publicFirst(a);
        byte[] changed = a.clone();
        changed[7] ^= 1;
        expect(0x6A80, ENV, 0, 2, changed, 0, "public changed duplicate wrote persistent");
        expect(0x6A80, ENV, 1, 2, b, 0, "public changed duplicate retained live handle");
        expect(0x9000, ENV, 0, 3, part(env, 0), 192, "public order control");
        expect(0x6A80, ENV, 2, 3, part(env, 2), 0, "public out-of-order chunk wrote persistent");
        expect(0x6A80, ENV, 1, 3, part(env, 1), 0, "public order refusal retained live handle");
        expect(0x6700, ENV, 0, 2, Arrays.copyOf(a, 100), 0, "public short middle chunk wrote persistent");
        expect(0x9000, ENV, 0, 3, part(env, 0), 192, "public mid-stream shape control");
        expect(0x6700, ENV, 1, 3, Arrays.copyOf(part(env, 1), 100), 0, "public mid-stream short chunk wrote persistent");
        expect(0x6A80, ENV, 1, 3, part(env, 1), 0, "public short middle refusal left a live stream");
        publicUpload(in, "public close length control");
        byte[] wrongLength = close(in);
        wrongLength[1] ^= 1;
        expect(0x6700, ENV + CLOSE, 0, 0, wrongLength, 0, "public close length wrote persistent");
        expect(0x6985, ENV + CLOSE, 0, 0, close(in), 0, "public close length retained live handle");
        publicUpload(in, "public close digest control");
        byte[] wrongDigest = close(in);
        wrongDigest[20] ^= 1;
        expect(0x6A80, ENV + CLOSE, 0, 0, wrongDigest, 0, "public bad close digest wrote persistent");
        expect(0x6985, ENV + CLOSE, 0, 0, close(in), 0, "public bad digest retained live handle");
        publicFirst(a);
        expect(0x9000, ENV + ABORT, 0, 0, EMPTY, 0, "public abort wrote persistent");
        expect(0x6A80, ENV, 1, 2, b, 0, "public abort retained live handle");
        publicFirst(a);
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6A80, ENV, 1, 2, b, 0, "public post-reset retry wrote persistent");
        expect(0x6985, ENV + CLOSE, 0, 0, close(in), 0, "public post-reset close wrote persistent");
        publicFirst(a);
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": public deselect wrote persistent");
        expect(0x6A80, ENV, 1, 2, b, 0, "public deselect retained live handle");
        publicFirst(a);
        expect(0x6985, SIGN + CLOSE, 0, 0, close(in), 0, "public foreign method wrote persistent");
        expect(0x6A80, ENV, 1, 2, b, 0, "public foreign refusal retained live handle");
        publicFirst(a);
        expect(0x6985, SIGN, 0, 2, Arrays.copyOf(transcript(194), 192), 0, "public foreign write wrote persistent");
        expect(0x6A80, ENV, 1, 2, b, 0, "public foreign write retained live handle");

        // Result refusals at CLOSE: prepare failure, invalid totals, producer failure.
        for (int[] c : new int[][] {{5, 0x6A80}, {6, 0x6700}, {7, 0x6700}}) {
            Rev4ShapeApplet.control = c[0];
            publicUpload(in, "public prepare control " + c[0]);
            expect(c[1], ENV + CLOSE, 0, 0, close(in), 0, "public prepare refusal " + c[0] + " wrote persistent");
            expect(0x6985, ENV + INFO, 0, 0, EMPTY, 0, "public prepare refusal " + c[0] + " retained live handle");
        }
        Rev4ShapeApplet.control = 0;
        Rev4ShapeApplet.failProduceAt = 2;
        expect(0x9000, ENV, 0, 3, part(env, 0), 192, "public digest pass failure control");
        expect(0x9000, ENV, 1, 3, part(env, 1), 192, "public digest pass failure control");
        expect(0x9000, ENV, 2, 3, part(env, 2), 192, "public digest pass failure control");
        expect(0x6F00, ENV + CLOSE, 0, 0, close(Arrays.copyOf(env, 576)), 0, "public digest pass failure wrote persistent");
        expect(0x6985, ENV + INFO, 0, 0, EMPTY, 0, "public digest pass failure retained live handle");
        Rev4ShapeApplet.failProduceAt = 0;
        // The engine was left mid-digest by that refusal; a staged CLOSE must not inherit it.
        publicUpload(in, "public close after digest pass failure control");
        expect(0x9000, ENV + CLOSE, 0, 0, close(in), 0, "public close after digest pass failure");
        expect(0x9000, ENV + ABORT, 0, 0, EMPTY, 0, "public abort after digest control");

        // Read refusals: 0 B, and the result handle is dead afterwards.
        Rev4ShapeApplet.failProduceAt = 2 + 2;
        publicClosed(in, "public read failure control");
        expect(0x9000, ENV + READ, 0, 2, EMPTY, 0, "public read before failure");
        expect(0x6F00, ENV + READ, 1, 2, EMPTY, 0, "public read failure wrote persistent");
        Rev4ShapeApplet.failProduceAt = 0;
        expect(0x6985, ENV + READ, 1, 2, EMPTY, 0, "public read failure retained live handle");
        publicClosed(in, "public bad read index control");
        expect(0x6A80, ENV + READ, 2, 2, EMPTY, 0, "public bad read index wrote persistent");
        expect(0x6985, ENV + READ, 0, 2, EMPTY, 0, "public bad read index retained live handle");
        publicClosed(in, "public bad read count control");
        expect(0x6A80, ENV + READ, 0, 3, EMPTY, 0, "public bad read count wrote persistent");
        expect(0x6985, ENV + INFO, 0, 0, EMPTY, 0, "public bad read count retained live handle");
        publicClosed(in, "public bad close read control");
        byte[] r2 = readAll(ENV, 2, "public read before bad close read");
        byte[] badCloseRead = close(r2);
        badCloseRead[9] ^= 1;
        expect(0x6A80, ENV + CLOSE_READ, 0, 0, badCloseRead, 0, "public bad close read wrote persistent");
        expect(0x6985, ENV + READ, 0, 2, EMPTY, 0, "public bad close read retained live handle");

        // A producer that is not deterministic is caught by the host digest check.
        Rev4ShapeApplet.control = 8;
        Rev4ShapeApplet.driftAfter = 2;
        byte[] d3 = publicClosed(in, "public drifting producer control");
        byte[] drifted = readAll(ENV, 2, "public drifting read wrote persistent");
        if (Arrays.equals(digest(drifted), Arrays.copyOfRange(d3, 3, 35))) throw new AssertionError("host did not detect a drifting producer");
        Rev4ShapeApplet.control = 0;
        expect(0x6A80, ENV + CLOSE_READ, 0, 0, close(drifted), 0, "drifting result close read wrote persistent");
    }

    // -------------------------------------------------------------- admission

    // INS 0x70 is chunked: the transcript is never staged, and the result,
    // signature || Cert_adm, is produced into RAM from the held signature and
    // the persistent Cert_adm record read in place. Every APDU writes 0 B.
    static void admissionStreams() throws Exception {
        reset();
        auth(false);
        byte[] t = transcript(320);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, 320);
        byte[] before = workspace.clone();
        int calls = Rev4ShapeApplet.chunkCalls;
        expect(0x9000, ADM, 0, 2, a, 0, "admission first chunk wrote persistent");
        expect(0x9000, ADM, 1, 2, b, 0, "admission last chunk wrote persistent");
        byte[] descriptor = expect(0x9000, ADM + CLOSE, 0, 0, close(t), 0, "admission close wrote persistent");
        int total = 73 + Rev4ShapeApplet.certLength, packets = (total + 191) / 192;
        checkDescriptor(descriptor, total, packets, "admission descriptor");
        if (!Arrays.equals(descriptor, expect(0x9000, ADM + INFO, 0, 0, EMPTY, 0, "admission info wrote persistent")))
            throw new AssertionError("admission info differs from the close descriptor");
        byte[] result = readAll(ADM, packets, "admission read wrote persistent");
        checkResult(descriptor, result, "admission read does not match the descriptor");
        checkAdmission(t, result, "admission result is not signature || Cert_adm");
        if (!Arrays.equals(Arrays.copyOf(result, 192), expect(0x9000, ADM + READ, 0, packets, EMPTY, 0, "admission read retry wrote persistent")))
            throw new AssertionError("admission read retry differs");
        expect(0x9000, ADM + CLOSE_READ, 0, 0, close(result), 0, "admission close read wrote persistent");
        expect(0x9000, ADM + CLOSE_READ, 0, 0, close(result), 0, "admission close read retry wrote persistent");
        if (!Arrays.equals(before, workspace)) throw new AssertionError("admission session staged the request or the result");
        if (Rev4ShapeApplet.chunkCalls - calls != 2) throw new AssertionError("admission handler did not receive each chunk once");
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission close retry wrote persistent");

        // Declared result maximum: 73 B signature + 1335 B Cert_adm = 1408 B.
        Rev4ShapeApplet.control = 9;
        admissionUpload(t, "admission maximum result control");
        byte[] maxDescriptor = expect(0x9000, ADM + CLOSE, 0, 0, close(t), 0, "admission maximum result wrote persistent");
        checkDescriptor(maxDescriptor, 1408, 8, "admission maximum descriptor");
        byte[] maxResult = readAll(ADM, 8, "admission maximum read wrote persistent");
        checkResult(maxDescriptor, maxResult, "admission maximum read");
        checkAdmission(t, maxResult, "admission maximum result is not signature || Cert_adm");
        Rev4ShapeApplet.control = 0;
        expect(0x9000, ADM + ABORT, 0, 0, EMPTY, 0, "admission abort after maximum result");

        // Upload refusals: nothing is staged, so every repeat is refused too.
        expect(0x9000, ADM, 0, 2, a, 0, "admission duplicate control");
        expect(0x6A80, ADM, 0, 2, a, 0, "admission identical duplicate wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission duplicate refusal retained live handle");
        expect(0x9000, ADM, 0, 2, a, 0, "admission changed duplicate control");
        byte[] changed = a.clone();
        changed[50] ^= 1;
        expect(0x6A80, ADM, 0, 2, changed, 0, "admission changed duplicate wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission changed duplicate left a live stream");
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission changed duplicate retained live handle");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission out-of-order first packet wrote persistent");
        expect(0x6700, ADM, 0, 3, a, 0, "admission oversized declaration wrote persistent");
        expect(0x6700, ADM, 0, 2, Arrays.copyOf(a, 100), 0, "admission short middle chunk wrote persistent");
        // Mid-stream shape refusal (index past the declared count), then the
        // valid last chunk: a live stream would accept it.
        expect(0x9000, ADM, 0, 2, a, 0, "admission mid-stream shape control");
        expect(0x6700, ADM, 2, 2, b, 0, "admission index past count wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission shape refusal left a live stream");
        admissionUpload(t, "admission close digest control");
        byte[] wrongDigest = close(t);
        wrongDigest[30] ^= 1;
        expect(0x6A80, ADM + CLOSE, 0, 0, wrongDigest, 0, "admission bad close digest wrote persistent");
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission bad digest retained live handle");
        admissionUpload(t, "admission close length control");
        byte[] wrongLength = close(t);
        wrongLength[1] ^= 1;
        expect(0x6700, ADM + CLOSE, 0, 0, wrongLength, 0, "admission close length wrote persistent");
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission close length retained live handle");
        expect(0x9000, ADM, 0, 2, a, 0, "admission early close control");
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission early close wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission early close retained live handle");
        expect(0x9000, ADM, 0, 2, a, 0, "admission abort control");
        expect(0x9000, ADM + ABORT, 0, 0, EMPTY, 0, "admission abort wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission abort retained live handle");
        expect(0x9000, ADM, 0, 2, a, 0, "admission reset control");
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6985, ADM + CLOSE, 0, 0, close(t), 0, "admission post-reset close wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission post-reset retry wrote persistent");
        expect(0x9000, ADM, 0, 2, a, 0, "admission deselect control");
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": admission deselect wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission deselect retained live handle");
        expect(0x9000, ADM, 0, 2, a, 0, "admission foreign control");
        expect(0x6985, ENV + READ, 0, 1, EMPTY, 0, "admission foreign method wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission foreign refusal retained live handle");

        // Handler refusals: parser, missing key, prepare failure, invalid totals.
        byte[] badTag = t.clone();
        badTag[0] = 0x55;
        expect(0x6A80, ADM, 0, 2, Arrays.copyOf(badTag, 192), 0, "admission parser refusal wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "admission parser refusal retained live handle");
        Rev4ShapeApplet.control = 4;
        expect(0x6A88, ADM, 0, 2, a, 0, "admission missing signing key wrote persistent");
        Rev4ShapeApplet.control = 0;
        byte[] lying = t.clone();
        lying[2] ^= 1;
        admissionUpload(lying, "admission transcript length control");
        expect(0x6A80, ADM + CLOSE, 0, 0, close(lying), 0, "admission transcript length refusal wrote persistent");
        for (int[] c : new int[][] {{5, 0x6A80}, {6, 0x6700}, {7, 0x6700}}) {
            Rev4ShapeApplet.control = c[0];
            admissionUpload(t, "admission prepare control " + c[0]);
            expect(c[1], ADM + CLOSE, 0, 0, close(t), 0, "admission prepare refusal " + c[0] + " wrote persistent");
            expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "admission prepare refusal " + c[0] + " retained live handle");
        }
        Rev4ShapeApplet.control = 0;
        Rev4ShapeApplet.failProduceAt = 2;
        admissionUpload(t, "admission digest pass failure control");
        expect(0x6F00, ADM + CLOSE, 0, 0, close(t), 0, "admission digest pass failure wrote persistent");
        expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "admission digest pass failure retained live handle");
        Rev4ShapeApplet.failProduceAt = packets + 2;
        admissionUpload(t, "admission read failure control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(t), 0, "admission read failure close");
        expect(0x9000, ADM + READ, 0, packets, EMPTY, 0, "admission read before failure");
        expect(0x6F00, ADM + READ, 1, packets, EMPTY, 0, "admission read failure wrote persistent");
        Rev4ShapeApplet.failProduceAt = 0;
        expect(0x6985, ADM + READ, 1, packets, EMPTY, 0, "admission read failure retained live handle");
        admissionUpload(t, "admission bad read index control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(t), 0, "admission bad read index close");
        expect(0x6A80, ADM + READ, packets, packets, EMPTY, 0, "admission bad read index wrote persistent");
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "admission bad read index retained live handle");

        // A drifting producer is caught by the host digest check.
        Rev4ShapeApplet.control = 8;
        Rev4ShapeApplet.driftAfter = packets;
        admissionUpload(t, "admission drifting producer control");
        byte[] d3 = expect(0x9000, ADM + CLOSE, 0, 0, close(t), 0, "admission drifting close");
        byte[] drifted = readAll(ADM, packets, "admission drifting read wrote persistent");
        if (Arrays.equals(digest(drifted), Arrays.copyOfRange(d3, 3, 35))) throw new AssertionError("host did not detect a drifting admission producer");
        Rev4ShapeApplet.control = 0;
        expect(0x6A80, ADM + CLOSE_READ, 0, 0, close(drifted), 0, "admission drifting close read wrote persistent");
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
        expect(0x9000, PUT, 0, 2, a, 192, "issuer accepted first chunk");
        // No unauthenticated APDU of any method can cancel or join the live upload.
        auth(false);
        byte[] in = chunk(320, 5);
        expect(0x6982, ENV, 0, 2, Arrays.copyOf(in, 192), 0, "unauthenticated public write cancelled issuer upload");
        expect(0x6982, SIGN, 0, 2, Arrays.copyOf(transcript(194), 192), 0, "unauthenticated chunked write cancelled issuer upload");
        expect(0x6982, ADM + ABORT, 0, 0, EMPTY, 0, "unauthenticated abort cancelled issuer upload");
        expect(0x6982, PUT + CLOSE, 0, 0, close(leaf), 0, "unauthenticated issuer close");
        // Every non-WRITE operation of a foreign method is refused the same way.
        // After each refusal an identical issuer duplicate (0 B, 9000) proves the
        // upload is still live; a fresh session would stage 192 B instead.
        int[][] foreign = {{ENV, CLOSE, 0}, {SIGN, CLOSE, 0}, {ADM, CLOSE, 0}, {ENV, INFO, 0}, {ADM, INFO, 0},
                {ENV, READ, 2}, {ADM, READ, 4}, {ENV, CLOSE_READ, 0}, {ADM, CLOSE_READ, 0}};
        String[] foreignNames = {"foreign close", "chunked close", "admission close", "foreign info", "admission info",
                "foreign read", "admission read", "foreign close read", "admission close read"};
        for (int i = 0; i < foreign.length; i++) {
            int op = foreign[i][1];
            byte[] data = op == CLOSE || op == CLOSE_READ ? close(in) : EMPTY;
            expect(0x6982, foreign[i][0] + op, 0, foreign[i][2], data, 0,
                    "unauthenticated " + foreignNames[i] + " cancelled issuer upload");
            auth(true);
            expect(0x9000, PUT, 0, 2, a, 0, "unauthenticated " + foreignNames[i] + " left no live issuer upload");
            auth(false);
        }
        auth(true);
        expect(0x9000, PUT, 1, 2, b, 5, "issuer accepted last chunk");
        byte[] receipt = expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 36, "issuer close receipt");
        for (int i = 0; i < 36; i++) {
            if (receipt[i] != (byte) (leaf[i % 197] ^ i ^ 36)) throw new AssertionError("issuer receipt bytes");
        }
        expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 0, "issuer close retry wrote");
        // F2 in the mode runtime: an authenticated foreign APDU kills the issuer upload.
        expect(0x9000, PUT, 0, 2, a, 192, "issuer foreign control");
        expect(0x6985, ENV, 0, 2, Arrays.copyOf(in, 192), 0, "issuer foreign write wrote persistent");
        expect(0x6A80, PUT, 1, 2, b, 0, "issuer foreign refusal retained live handle");
        // A finished issuer session does not block a public caller.
        auth(false);
        signSession(transcript(194), "public session after issuer receipt");
        // An authenticated foreign APDU invalidates a public session, with 0 B.
        publicFirst(Arrays.copyOf(in, 192));
        auth(true);
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "authenticated foreign refusal wrote persistent");
        auth(false);
        expect(0x6A80, ENV, 1, 2, Arrays.copyOfRange(in, 192, 320), 0, "authenticated foreign refusal retained public handle");
    }

    // ----------------------------------------------------------- request bounds

    // The declared request maximum bounds the running total, not only the packet
    // count: 10 x 192 > 1792 (0x10), 11 x 192 > 2048 (0x20), 2 x 192 > 320 (0x70).
    // An in-count upload whose last chunk takes the total one byte past the
    // maximum, or a full chunk past it, is refused 6700 with 0 B before the
    // handler, and the stream is dead; an upload at exactly the maximum is the
    // accepted control.
    static void requestBounds() throws Exception {
        reset();
        auth(false);
        int[][] families = {{ENV, 1792}, {SIGN, 2048}, {ADM, 320}};
        String[] names = {"public", "chunked", "admission"};
        for (int f = 0; f < families.length; f++) {
            int family = families[f][0], max = families[f][1], count = (max + 191) / 192;
            String name = names[f];
            for (int total : new int[] {max + 1, count * 192}) {
                byte[] over = family == ENV ? chunk(total, 11) : transcript(total);
                int calls = Rev4ShapeApplet.chunkCalls;
                for (int i = 0; i < count - 1; i++) {
                    expect(0x9000, family, i, count, part(over, i), family == ENV ? 192 : 0, name + " over-maximum control");
                }
                byte[] last = part(over, count - 1);
                expect(0x6700, family, count - 1, count, last, 0, name + " request over maximum wrote persistent");
                if (family != ENV && Rev4ShapeApplet.chunkCalls - calls != count - 1)
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
            byte[] exact = family == ENV ? chunk(max, 11) : transcript(max);
            for (int i = 0; i < count; i++) {
                byte[] p = part(exact, i);
                expect(0x9000, family, i, count, p, family == ENV ? p.length : 0, name + " request at maximum control");
            }
            byte[] closed = expect(0x9000, family + CLOSE, 0, 0, close(exact), 0, name + " request at maximum close wrote persistent");
            if (family == SIGN) {
                verify(closed, exact, "chunked request at maximum signature");
            } else {
                int total = family == ENV ? max : 73 + Rev4ShapeApplet.certLength;
                checkDescriptor(closed, total, (total + 191) / 192, name + " request at maximum descriptor");
                expect(0x9000, family + ABORT, 0, 0, EMPTY, 0, name + " request at maximum abort");
            }
        }
    }

    // -------------------------------------------------------------- admission

    // Direct route: the caller chooses the arrays. A persistent output or caller
    // workspace is refused before any handler callback; RAM spans are accepted.
    static void spanAdmission() throws Exception {
        reset();
        auth(false);
        byte[] t = transcript(194);
        byte[] a = Arrays.copyOf(t, 192), b = Arrays.copyOfRange(t, 192, t.length);
        int calls = Rev4ShapeApplet.chunkCalls;
        Rev4ShapeApplet.output = 2;
        expect(0x6985, SIGN, 0, 2, a, 0, "persistent caller workspace admitted on chunk");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.chunkCalls != calls) throw new AssertionError("persistent caller workspace admitted on chunk: handler ran");
        sendChunks(t, "chunked admission control");
        int finishes = Rev4ShapeApplet.finishCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "persistent response admitted on chunked close");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.finishCalls != finishes) throw new AssertionError("persistent response admitted on chunked close: handler ran");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked admission refusal retained live handle");
        // The caller-workspace half of the same CLOSE admission: the handler
        // scratch passed to Finish must be RAM as well.
        sendChunks(t, "chunked close workspace control");
        finishes = Rev4ShapeApplet.finishCalls;
        Rev4ShapeApplet.output = 2;
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "persistent caller workspace admitted on chunked close");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.finishCalls != finishes) throw new AssertionError("persistent caller workspace admitted on chunked close: handler ran");
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked close workspace refusal retained live handle");
        signSession(t, "RAM caller workspace chunked close control");
        sendChunks(t, "transient chunked response control");
        Rev4ShapeApplet.output = 3;
        verify(expect(0x9000, SIGN + CLOSE, 0, 0, close(t), 0, "transient chunked response wrote persistent"), t,
                "transient chunked response");
        Rev4ShapeApplet.output = 0;

        byte[] in = chunk(320, 5);
        int packets = 2;
        for (int span : new int[] {1, 2}) {
            String kind = span == 1 ? "persistent response" : "persistent caller workspace";
            publicUpload(in, kind + " public control");
            int prepared = Rev4ShapeApplet.prepareCalls;
            Rev4ShapeApplet.output = span;
            expect(0x6985, ENV + CLOSE, 0, 0, close(in), 0, kind + " admitted on public close");
            Rev4ShapeApplet.output = 0;
            if (Rev4ShapeApplet.prepareCalls != prepared) throw new AssertionError(kind + " admitted on public close: handler ran");
            expect(0x6985, ENV + CLOSE, 0, 0, close(in), 0, kind + " public refusal retained live handle");
        }
        publicClosed(in, "persistent read span control");
        int produced = Rev4ShapeApplet.produceCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ENV + READ, 0, packets, EMPTY, 0, "persistent read span admitted");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.produceCalls != produced) throw new AssertionError("persistent read span admitted: handler ran");
        expect(0x6985, ENV + READ, 0, packets, EMPTY, 0, "persistent read refusal retained live handle");
        // The caller-workspace half of READ admission: the producer scratch must be RAM.
        publicClosed(in, "public read workspace control");
        produced = Rev4ShapeApplet.produceCalls;
        Rev4ShapeApplet.output = 2;
        expect(0x6985, ENV + READ, 0, packets, EMPTY, 0, "persistent caller workspace admitted on public read");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.produceCalls != produced) throw new AssertionError("persistent caller workspace admitted on public read: handler ran");
        expect(0x6985, ENV + READ, 0, packets, EMPTY, 0, "public read workspace refusal retained live handle");
        byte[] ramRead = publicClosed(in, "RAM caller workspace public read control");
        checkResult(ramRead, readAll(ENV, packets, "RAM caller workspace public read wrote persistent"), "RAM caller workspace public read");
        expect(0x9000, ENV + ABORT, 0, 0, EMPTY, 0, "RAM caller workspace public read abort");
        publicClosed(in, "persistent descriptor span control");
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ENV + INFO, 0, 0, EMPTY, 0, "persistent descriptor span admitted");
        Rev4ShapeApplet.output = 0;
        expect(0x6985, ENV + INFO, 0, 0, EMPTY, 0, "persistent descriptor refusal retained live handle");
        // Chunked admission result: the same admission at CLOSE and READ.
        byte[] adm = transcript(320);
        admissionUpload(adm, "chunked result admission control");
        int preparedAdm = Rev4ShapeApplet.prepareCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ADM + CLOSE, 0, 0, close(adm), 0, "persistent response admitted on admission close");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.prepareCalls != preparedAdm) throw new AssertionError("persistent response admitted on admission close: handler ran");
        expect(0x6985, ADM + CLOSE, 0, 0, close(adm), 0, "admission close refusal retained live handle");
        int admPackets = (73 + Rev4ShapeApplet.certLength + 191) / 192;
        admissionUpload(adm, "chunked read admission control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(adm), 0, "chunked read admission close");
        int producedAdm = Rev4ShapeApplet.produceCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ADM + READ, 1, admPackets, EMPTY, 0, "persistent read span admitted on admission");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.produceCalls != producedAdm) throw new AssertionError("persistent read span admitted on admission: handler ran");
        expect(0x6985, ADM + READ, 1, admPackets, EMPTY, 0, "admission read refusal retained live handle");
        // Caller-workspace half at the admission CLOSE (Prepare) and READ (Produce).
        admissionUpload(adm, "admission close workspace control");
        preparedAdm = Rev4ShapeApplet.prepareCalls;
        Rev4ShapeApplet.output = 2;
        expect(0x6985, ADM + CLOSE, 0, 0, close(adm), 0, "persistent caller workspace admitted on admission close");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.prepareCalls != preparedAdm) throw new AssertionError("persistent caller workspace admitted on admission close: handler ran");
        expect(0x6985, ADM + CLOSE, 0, 0, close(adm), 0, "admission close workspace refusal retained live handle");
        admissionUpload(adm, "admission read workspace control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(adm), 0, "admission read workspace close");
        producedAdm = Rev4ShapeApplet.produceCalls;
        Rev4ShapeApplet.output = 2;
        expect(0x6985, ADM + READ, 0, admPackets, EMPTY, 0, "persistent caller workspace admitted on admission read");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.produceCalls != producedAdm) throw new AssertionError("persistent caller workspace admitted on admission read: handler ran");
        expect(0x6985, ADM + READ, 0, admPackets, EMPTY, 0, "admission read workspace refusal retained live handle");
        admissionUpload(adm, "RAM caller workspace admission read control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(adm), 0, "RAM caller workspace admission close wrote persistent");
        checkAdmission(adm, readAll(ADM, admPackets, "RAM caller workspace admission read wrote persistent"), "RAM caller workspace admission result");
        expect(0x9000, ADM + ABORT, 0, 0, EMPTY, 0, "RAM caller workspace admission abort");
        // Transient response span: the whole admission flow is accepted.
        Rev4ShapeApplet.output = 3;
        admissionUpload(adm, "transient admission response control");
        byte[] admD = expect(0x9000, ADM + CLOSE, 0, 0, close(adm), 0, "transient admission close wrote persistent");
        checkAdmission(adm, readAll(ADM, admPackets, "transient admission read wrote persistent"), "transient admission result");
        Rev4ShapeApplet.output = 0;
        checkDescriptor(admD, 73 + Rev4ShapeApplet.certLength, admPackets, "transient admission descriptor");
        expect(0x9000, ADM + ABORT, 0, 0, EMPTY, 0, "admission abort after transient control");
        // F1 in the mode runtime: a persistent issuer response is refused before the handler.
        byte[] leaf = chunk(197, 9);
        auth(true);
        expect(0x9000, PUT, 0, 2, Arrays.copyOf(leaf, 192), 192, "issuer admission control");
        expect(0x9000, PUT, 1, 2, Arrays.copyOfRange(leaf, 192, 197), 5, "issuer admission tail");
        int staged = Rev4ShapeApplet.stagedCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "persistent response admitted on issuer close");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.stagedCalls != staged) throw new AssertionError("persistent response admitted on issuer close: handler ran");
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "issuer admission refusal retained live handle");
        auth(false);
        // Transient response span: the whole public flow is accepted.
        Rev4ShapeApplet.output = 3;
        byte[] d = publicClosed(in, "transient public response control");
        checkResult(d, readAll(ENV, packets, "transient public read wrote persistent"), "transient public read");
        Rev4ShapeApplet.output = 0;
    }

    // ------------------------------------------------------- runtime refusals

    // Direct runtime calls: begin refuses a streamed result for an authenticated
    // method, an unknown mode and a missing request stream before any effect; a
    // valid chunked call is the accepted control.
    static void runtimeRefusals(Object session) {
        reset();
        Rev4ShapeStreamEndpoint endpoint = (Rev4ShapeStreamEndpoint) session;
        byte[] io = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        Object[][] cases = {
            {"chunked method without request stream admitted", Rev4ShapeStreamEndpoint.MODE_CHUNKED, false, true},
            {"authenticated streamed result admitted", Rev4ShapeStreamEndpoint.MODE_AUTHENTICATED, true, true},
            {"unknown stream mode admitted", (byte) 3, true, false},
            {"public method without request stream admitted", Rev4ShapeStreamEndpoint.MODE_PUBLIC_INVALIDATE, false, true},
        };
        for (Object[] c : cases) {
            String label = (String) c[0];
            boolean request = (Boolean) c[2], response = (Boolean) c[3];
            NvmLedger.reset();
            try {
                endpoint.dispatch((byte) 2, Rev4ShapeStreamEndpoint.OP_WRITE_OR_INVOKE, (Byte) c[1],
                        request, (short) 64, (short) 32, response, (short) 64, (short) 32, response ? (short) -1 : (short) 73,
                        Rev4ShapeApplet.installed.logic, (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                        io, (short) 0, (short) 255, true);
                throw new AssertionError(label);
            } catch (Rev4ShapeStreamEndpoint.StreamStatusWordException e) {
                if (e.getStatusWord() != (short) 0x6A84) throw new AssertionError(label + ": " + Integer.toHexString(e.getStatusWord() & 65535));
            }
            if (NvmLedger.persistent != 0) throw new AssertionError(label + ": wrote persistent");
        }
        NvmLedger.reset();
        Arrays.fill(io, (byte) 0);
        io[0] = 0x54;
        io[2] = 1;
        try {
            endpoint.dispatch((byte) 2, Rev4ShapeStreamEndpoint.OP_WRITE_OR_INVOKE, Rev4ShapeStreamEndpoint.MODE_CHUNKED,
                    true, (short) 64, (short) 32, false, (short) 0, (short) 0, (short) 73,
                    Rev4ShapeApplet.installed.logic, (byte) 0, (byte) 1, io, (short) 0, (short) 4, io, (short) 0, (short) 255,
                    io, (short) 0, (short) 255, false);
        } catch (Rev4ShapeStreamEndpoint.StreamStatusWordException e) {
            throw new AssertionError("chunked runtime control refused: " + Integer.toHexString(e.getStatusWord() & 65535));
        }
        if (NvmLedger.persistent != 0) throw new AssertionError("chunked runtime control wrote persistent");
        endpoint.abort(Rev4ShapeStreamEndpoint.ABORT_EXPLICIT);
    }

    // ---------------------------------------------------------------- helpers

    static void reset() {
        Rev4ShapeApplet.control = 0;
        Rev4ShapeApplet.failProduceAt = 0;
        Rev4ShapeApplet.output = 0;
        expectAny(SIGN + ABORT);
    }

    static void expectAny(int ins) {
        auth(true);
        try {
            send(ins, 0, 0, EMPTY);
        } catch (ISOException e) {
            throw new AssertionError("abort before scenario: " + Integer.toHexString(e.getReason() & 0xFFFF));
        }
    }

    static void signSession(byte[] t, String label) throws Exception {
        sendChunks(t, label);
        verify(expect(0x9000, SIGN + CLOSE, 0, 0, close(t), 0, label + " close wrote persistent"), t, label);
    }

    static void sendChunks(byte[] t, String label) {
        int count = (t.length + 191) / 192;
        for (int i = 0; i < count; i++) expect(0x9000, SIGN, i, count, part(t, i), 0, label);
    }

    static void publicFirst(byte[] a) {
        expect(0x9000, ENV, 0, 2, a, 192, "public first chunk control");
    }

    static void publicUpload(byte[] in, String label) {
        expect(0x9000, ENV, 0, 2, Arrays.copyOf(in, 192), 192, label);
        expect(0x9000, ENV, 1, 2, Arrays.copyOfRange(in, 192, 320), 128, label);
    }

    static byte[] publicClosed(byte[] in, String label) {
        publicUpload(in, label);
        byte[] d = expect(0x9000, ENV + CLOSE, 0, 0, close(in), 0, label + " close");
        checkDescriptor(d, 320, 2, label);
        return d;
    }

    static void admissionUpload(byte[] t, String label) {
        expect(0x9000, ADM, 0, 2, Arrays.copyOf(t, 192), 0, label);
        expect(0x9000, ADM, 1, 2, Arrays.copyOfRange(t, 192, t.length), 0, label);
    }

    // Envelope result: a deterministic transform of the staged request.
    static void checkEnvelope(byte[] in, byte[] result, String label) {
        for (int at = 0; at < result.length; at++) {
            if (result[at] != (byte) (in[at % in.length] ^ 0x5A ^ at)) throw new AssertionError(label);
        }
    }

    // Admission result: the 73 B signature record over the whole transcript,
    // then the Cert_adm record bytes as stored.
    static void checkAdmission(byte[] transcript, byte[] result, String label) {
        verify(Arrays.copyOf(result, 73), transcript, label);
        byte[] cert = Rev4ShapeApplet.installed.logic.certAdm;
        for (int i = 73; i < result.length; i++) {
            if (result[i] != cert[i - 73]) throw new AssertionError(label + ": Cert_adm byte " + (i - 73));
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

    static void verify(byte[] response, byte[] transcript, String label) {
        if (response.length != 73) throw new AssertionError(label + ": response length " + response.length);
        int length = response[0] & 255;
        Signature verifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        verifier.init(Rev4ShapeApplet.installed.logic.keys.getPublic(), Signature.MODE_VERIFY);
        if (length < 8 || length > 72 ||
                !verifier.verify(transcript, (short) 0, (short) transcript.length, response, (short) 1, (short) length))
            throw new AssertionError(label);
        for (int i = length + 1; i < 73; i++) {
            if (response[i] != 0) throw new AssertionError(label + ": padding");
        }
    }

    static void auth(boolean value) {
        Rev4ShapeApplet.authenticated = value;
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

    static byte[] transcript(int total) {
        byte[] t = chunk(total, 3);
        int body = total - 3;
        t[0] = 0x54;
        t[1] = (byte) (body >> 8);
        t[2] = (byte) body;
        return t;
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
