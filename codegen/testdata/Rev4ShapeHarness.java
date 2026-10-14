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
            if (only.equals("all") || only.equals("authority")) authority();
            if (direct && (only.equals("all") || only.equals("admission"))) admission();
        }
        runtimeRefusals(session);
        System.out.println("stream modes: chunked, public and authority controls green on adapter and direct routes");
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
        expect(0x6985, SIGN + CLOSE, 0, 0, close(t), 0, "chunked changed duplicate retained live handle");
        expect(0x9000, SIGN, 0, 2, a, 0, "chunked identical duplicate control");
        expect(0x6A80, SIGN, 0, 2, a, 0, "chunked identical duplicate wrote persistent");
        expect(0x6A80, SIGN, 1, 2, b, 0, "chunked identical duplicate retained live handle");

        // Invalid lengths and close declarations.
        expect(0x6700, SIGN, 0, 2, Arrays.copyOf(a, 100), 0, "chunked short middle chunk wrote persistent");
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

    static void publicStreams() throws Exception {
        reset();
        auth(false); // public methods are admitted without authentication
        byte[] in = chunk(320, 5);
        byte[] a = Arrays.copyOf(in, 192), b = Arrays.copyOfRange(in, 192, 320);
        expect(0x9000, ADM, 0, 2, a, 192, "public accepted first chunk");
        expect(0x9000, ADM, 1, 2, b, 128, "public accepted last chunk");
        expect(0x9000, ADM, 1, 2, b, 0, "public identical duplicate wrote");
        int prepared = Rev4ShapeApplet.prepareCalls;
        byte[] descriptor = expect(0x9000, ADM + CLOSE, 0, 0, close(in), 0, "public close wrote persistent");
        if (Rev4ShapeApplet.prepareCalls != prepared + 1) throw new AssertionError("public result not prepared once");
        int total = 73 + 4 * 320, packets = (total + 191) / 192;
        checkDescriptor(descriptor, total, packets, "public descriptor");
        if (!Arrays.equals(descriptor, expect(0x9000, ADM + INFO, 0, 0, EMPTY, 0, "public info wrote persistent")))
            throw new AssertionError("public info differs from the close descriptor");
        byte[] result = readAll(ADM, packets, "public read wrote persistent");
        checkResult(descriptor, result, "public read does not match the descriptor");
        for (int at = 73; at < total; at++) {
            int body = at - 73;
            if (result[at] != (byte) (in[body % 320] ^ body ^ (body >> 8))) throw new AssertionError("public result bytes");
        }
        if (!Arrays.equals(Arrays.copyOfRange(result, 3 * 192, 4 * 192), expect(0x9000, ADM + READ, 3, packets, EMPTY, 0, "public read retry wrote persistent")))
            throw new AssertionError("public read retry differs");
        expect(0x9000, ADM + CLOSE_READ, 0, 0, close(result), 0, "public close read wrote persistent");
        expect(0x9000, ADM + CLOSE_READ, 0, 0, close(result), 0, "public close read retry wrote persistent");
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "public read after close read wrote persistent");

        // Bounds: 1792 B upload and 1792 B result through the envelope method.
        byte[] env = chunk(1792, 7);
        for (int i = 0; i < 10; i++) {
            byte[] p = part(env, i);
            expect(0x9000, ENV, i, 10, p, p.length, "public bounded chunk");
        }
        byte[] envDescriptor = expect(0x9000, ENV + CLOSE, 0, 0, close(env), 0, "public bounded close wrote persistent");
        checkDescriptor(envDescriptor, 1792, 10, "public bounded descriptor");
        byte[] envResult = readAll(ENV, 10, "public bounded read wrote persistent");
        checkResult(envDescriptor, envResult, "public bounded read does not match the descriptor");
        for (int at = 0; at < 1792; at++) {
            if (envResult[at] != (byte) (env[at] ^ 0x5A ^ at)) throw new AssertionError("public bounded result bytes");
        }
        expect(0x9000, ENV + CLOSE_READ, 0, 0, close(envResult), 0, "public bounded close read wrote persistent");
        expect(0x6700, ENV, 0, 11, part(env, 0), 0, "public oversized declaration wrote persistent");
        // Declared result maximum: exactly 1408 B is accepted.
        Rev4ShapeApplet.control = 9;
        publicUpload(in, "public maximum result control");
        byte[] maxDescriptor = expect(0x9000, ADM + CLOSE, 0, 0, close(in), 0, "public maximum result wrote persistent");
        checkDescriptor(maxDescriptor, 1408, 8, "public maximum descriptor");
        byte[] maxResult = readAll(ADM, 8, "public maximum read wrote persistent");
        checkResult(maxDescriptor, maxResult, "public maximum read");
        Rev4ShapeApplet.control = 0;
        // A WRITE while the result is pending is refused and kills the result.
        expect(0x6A80, ADM, 0, 2, a, 0, "public write during pending read wrote persistent");
        expect(0x6985, ADM + CLOSE_READ, 0, 0, close(maxResult), 0, "public pending read refusal retained live handle");

        // Upload refusals: 0 B, and the stream is dead afterwards.
        publicFirst(a);
        byte[] changed = a.clone();
        changed[7] ^= 1;
        expect(0x6A80, ADM, 0, 2, changed, 0, "public changed duplicate wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "public changed duplicate retained live handle");
        expect(0x9000, ENV, 0, 3, part(env, 0), 192, "public order control");
        expect(0x6A80, ENV, 2, 3, part(env, 2), 0, "public out-of-order chunk wrote persistent");
        expect(0x6A80, ENV, 1, 3, part(env, 1), 0, "public order refusal retained live handle");
        expect(0x6700, ADM, 0, 2, Arrays.copyOf(a, 100), 0, "public short middle chunk wrote persistent");
        publicUpload(in, "public close length control");
        byte[] wrongLength = close(in);
        wrongLength[1] ^= 1;
        expect(0x6700, ADM + CLOSE, 0, 0, wrongLength, 0, "public close length wrote persistent");
        expect(0x6985, ADM + CLOSE, 0, 0, close(in), 0, "public close length retained live handle");
        publicUpload(in, "public close digest control");
        byte[] wrongDigest = close(in);
        wrongDigest[20] ^= 1;
        expect(0x6A80, ADM + CLOSE, 0, 0, wrongDigest, 0, "public bad close digest wrote persistent");
        expect(0x6985, ADM + CLOSE, 0, 0, close(in), 0, "public bad digest retained live handle");
        publicFirst(a);
        expect(0x9000, ADM + ABORT, 0, 0, EMPTY, 0, "public abort wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "public abort retained live handle");
        publicFirst(a);
        simulator.reset();
        simulator.selectApplet(aid);
        expect(0x6A80, ADM, 1, 2, b, 0, "public post-reset retry wrote persistent");
        expect(0x6985, ADM + CLOSE, 0, 0, close(in), 0, "public post-reset close wrote persistent");
        publicFirst(a);
        NvmLedger.reset();
        simulator.selectApplet(other);
        simulator.selectApplet(aid);
        if (NvmLedger.persistent != 0) throw new AssertionError(route + ": public deselect wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "public deselect retained live handle");
        publicFirst(a);
        expect(0x6985, SIGN + CLOSE, 0, 0, close(in), 0, "public foreign method wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "public foreign refusal retained live handle");
        publicFirst(a);
        expect(0x6985, SIGN, 0, 2, Arrays.copyOf(transcript(194), 192), 0, "public foreign write wrote persistent");
        expect(0x6A80, ADM, 1, 2, b, 0, "public foreign write retained live handle");

        // Result refusals at CLOSE: prepare failure, invalid totals, producer failure.
        for (int[] c : new int[][] {{5, 0x6A80}, {6, 0x6700}, {7, 0x6700}}) {
            Rev4ShapeApplet.control = c[0];
            publicUpload(in, "public prepare control " + c[0]);
            expect(c[1], ADM + CLOSE, 0, 0, close(in), 0, "public prepare refusal " + c[0] + " wrote persistent");
            expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "public prepare refusal " + c[0] + " retained live handle");
        }
        Rev4ShapeApplet.control = 0;
        Rev4ShapeApplet.failProduceAt = 2;
        publicUpload(in, "public digest pass failure control");
        expect(0x6F00, ADM + CLOSE, 0, 0, close(in), 0, "public digest pass failure wrote persistent");
        expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "public digest pass failure retained live handle");

        // Read refusals: 0 B, and the result handle is dead afterwards.
        Rev4ShapeApplet.failProduceAt = packets + 2;
        publicUpload(in, "public read failure control");
        expect(0x9000, ADM + CLOSE, 0, 0, close(in), 0, "public read failure close");
        expect(0x9000, ADM + READ, 0, packets, EMPTY, 0, "public read before failure");
        expect(0x6F00, ADM + READ, 1, packets, EMPTY, 0, "public read failure wrote persistent");
        Rev4ShapeApplet.failProduceAt = 0;
        expect(0x6985, ADM + READ, 1, packets, EMPTY, 0, "public read failure retained live handle");
        publicClosed(in, packets, "public bad read index control");
        expect(0x6A80, ADM + READ, packets, packets, EMPTY, 0, "public bad read index wrote persistent");
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "public bad read index retained live handle");
        publicClosed(in, packets, "public bad read count control");
        expect(0x6A80, ADM + READ, 0, packets + 1, EMPTY, 0, "public bad read count wrote persistent");
        expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "public bad read count retained live handle");
        byte[] d2 = publicClosed(in, packets, "public bad close read control");
        byte[] r2 = readAll(ADM, packets, "public read before bad close read");
        byte[] badCloseRead = close(r2);
        badCloseRead[9] ^= 1;
        expect(0x6A80, ADM + CLOSE_READ, 0, 0, badCloseRead, 0, "public bad close read wrote persistent");
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "public bad close read retained live handle");

        // A producer that is not deterministic is caught by the host digest check.
        Rev4ShapeApplet.control = 8;
        byte[] d3 = publicClosed(in, packets, "public drifting producer control");
        byte[] drifted = readAll(ADM, packets, "public drifting read wrote persistent");
        if (Arrays.equals(digest(drifted), Arrays.copyOfRange(d3, 3, 35))) throw new AssertionError("host did not detect a drifting producer");
        Rev4ShapeApplet.control = 0;
        expect(0x6A80, ADM + CLOSE_READ, 0, 0, close(drifted), 0, "drifting result close read wrote persistent");
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
        expect(0x6982, ADM, 0, 2, Arrays.copyOf(in, 192), 0, "unauthenticated public write cancelled issuer upload");
        expect(0x6982, SIGN, 0, 2, Arrays.copyOf(transcript(194), 192), 0, "unauthenticated chunked write cancelled issuer upload");
        expect(0x6982, ADM + ABORT, 0, 0, EMPTY, 0, "unauthenticated abort cancelled issuer upload");
        expect(0x6982, PUT + CLOSE, 0, 0, close(leaf), 0, "unauthenticated issuer close");
        auth(true);
        expect(0x9000, PUT, 1, 2, b, 5, "issuer accepted last chunk");
        byte[] receipt = expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 36, "issuer close receipt");
        for (int i = 0; i < 36; i++) {
            if (receipt[i] != (byte) (leaf[i % 197] ^ i ^ 36)) throw new AssertionError("issuer receipt bytes");
        }
        expect(0x9000, PUT + CLOSE, 0, 0, close(leaf), 0, "issuer close retry wrote");
        // F2 in the mode runtime: an authenticated foreign APDU kills the issuer upload.
        expect(0x9000, PUT, 0, 2, a, 192, "issuer foreign control");
        expect(0x6985, ADM, 0, 2, Arrays.copyOf(in, 192), 0, "issuer foreign write wrote persistent");
        expect(0x6A80, PUT, 1, 2, b, 0, "issuer foreign refusal retained live handle");
        // A finished issuer session does not block a public caller.
        auth(false);
        signSession(transcript(194), "public session after issuer receipt");
        // An authenticated foreign APDU invalidates a public session, with 0 B.
        publicFirst(Arrays.copyOf(in, 192));
        auth(true);
        expect(0x6985, PUT + CLOSE, 0, 0, close(leaf), 0, "authenticated foreign refusal wrote persistent");
        auth(false);
        expect(0x6A80, ADM, 1, 2, Arrays.copyOfRange(in, 192, 320), 0, "authenticated foreign refusal retained public handle");
    }

    // -------------------------------------------------------------- admission

    // Direct route: the caller chooses the arrays. A persistent output or caller
    // workspace is refused before any handler callback; RAM spans are accepted.
    static void admission() throws Exception {
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
        sendChunks(t, "transient chunked response control");
        Rev4ShapeApplet.output = 3;
        verify(expect(0x9000, SIGN + CLOSE, 0, 0, close(t), 0, "transient chunked response wrote persistent"), t,
                "transient chunked response");
        Rev4ShapeApplet.output = 0;

        byte[] in = chunk(320, 5);
        int packets = (73 + 4 * 320 + 191) / 192;
        for (int span : new int[] {1, 2}) {
            String kind = span == 1 ? "persistent response" : "persistent caller workspace";
            publicUpload(in, kind + " public control");
            int prepared = Rev4ShapeApplet.prepareCalls;
            Rev4ShapeApplet.output = span;
            expect(0x6985, ADM + CLOSE, 0, 0, close(in), 0, kind + " admitted on public close");
            Rev4ShapeApplet.output = 0;
            if (Rev4ShapeApplet.prepareCalls != prepared) throw new AssertionError(kind + " admitted on public close: handler ran");
            expect(0x6985, ADM + CLOSE, 0, 0, close(in), 0, kind + " public refusal retained live handle");
        }
        publicClosed(in, packets, "persistent read span control");
        int produced = Rev4ShapeApplet.produceCalls;
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "persistent read span admitted");
        Rev4ShapeApplet.output = 0;
        if (Rev4ShapeApplet.produceCalls != produced) throw new AssertionError("persistent read span admitted: handler ran");
        expect(0x6985, ADM + READ, 0, packets, EMPTY, 0, "persistent read refusal retained live handle");
        publicClosed(in, packets, "persistent descriptor span control");
        Rev4ShapeApplet.output = 1;
        expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "persistent descriptor span admitted");
        Rev4ShapeApplet.output = 0;
        expect(0x6985, ADM + INFO, 0, 0, EMPTY, 0, "persistent descriptor refusal retained live handle");
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
        byte[] d = publicClosed(in, packets, "transient public response control");
        checkResult(d, readAll(ADM, packets, "transient public read wrote persistent"), "transient public read");
        Rev4ShapeApplet.output = 0;
    }

    // ------------------------------------------------------- runtime refusals

    // Direct runtime calls: begin refuses a streamed result outside the public
    // mode, an unknown mode and a missing request stream before any effect; a
    // valid chunked call is the accepted control.
    static void runtimeRefusals(Object session) {
        reset();
        Rev4ShapeStreamEndpoint endpoint = (Rev4ShapeStreamEndpoint) session;
        byte[] io = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        Object[][] cases = {
            {"chunked streamed result admitted", Rev4ShapeStreamEndpoint.MODE_CHUNKED, true, true},
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
        expect(0x9000, ADM, 0, 2, a, 192, "public first chunk control");
    }

    static void publicUpload(byte[] in, String label) {
        expect(0x9000, ADM, 0, 2, Arrays.copyOf(in, 192), 192, label);
        expect(0x9000, ADM, 1, 2, Arrays.copyOfRange(in, 192, 320), 128, label);
    }

    static byte[] publicClosed(byte[] in, int packets, String label) {
        publicUpload(in, label);
        byte[] d = expect(0x9000, ADM + CLOSE, 0, 0, close(in), 0, label + " close");
        checkDescriptor(d, 73 + 4 * 320, packets, label);
        return d;
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
