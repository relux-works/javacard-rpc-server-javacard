package io.jcrpc.rev4shape.server;

import javacard.framework.*;
import javacard.security.*;

/**
 * Test fixture for the per-method stream modes. Handlers model the Auth
 * shapes: chunked ECDSA signatures over an incrementally parsed transcript
 * (INS 0x20 short, INS 0x70 with a signature + Cert_adm streamed result), an
 * authenticated issuer upload, and a public option-A streamed result (INS
 * 0x10), all results produced into RAM. Every array element store is reported to NvmLedger, classified by
 * array identity; Signature and MessageDigest internal state are not visible
 * to the ledger.
 */
public final class Rev4ShapeApplet extends Applet {
    static Rev4ShapeApplet installed;
    static boolean authenticated = true, direct = false;
    // 0 accept; 1 finish fails after writing output; 2 finish returns 74;
    // 3 chunk handler fails on packet 1; 4 signing key missing; 5 prepare fails;
    // 6 prepare returns max + 1; 7 prepare returns 0; 8 producer drifts on reads;
    // 9 prepare returns exactly the declared maximum.
    static int control = 0;
    // Producer call number (1-based, counted from prepare) that fails; 0 never.
    static int failProduceAt = 0;
    // Direct route spans: 0 APDU buffer, 1 persistent response,
    // 2 persistent caller workspace, 3 transient response.
    static int output = 0;
    static int chunkCalls = 0, maxChunk = 0, finishCalls = 0, prepareCalls = 0, produceCalls = 0, stagedCalls = 0;
    static boolean chunkFromPersistent = false;
    // Admission Cert_adm length and the producer call after which a drifting
    // producer changes its bytes.
    static short certLength = 600;
    static int driftAfter = 8;

    final Logic logic = new Logic();
    final Rev4ShapeStreamAPDUAdapter adapter = new Rev4ShapeStreamAPDUAdapter(logic);
    final byte[] noData = new byte[0];
    final byte[] persistentSpan = new byte[255];
    final byte[] transientSpan = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);

    public static void install(byte[] b, short o, byte l) {
        new Rev4ShapeApplet().register();
    }

    Rev4ShapeApplet() {
        installed = this;
    }

    public void deselect() {
        adapter.deselect();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        NvmLedger.apdu = buf;
        if (logic.isStreamInstruction(buf[ISO7816.OFFSET_INS])) {
            if (!direct) {
                adapter.processIfStream(apdu, authenticated);
                return;
            }
            // Auth-shaped route: one APDU buffer is request, response and caller workspace.
            byte ins = buf[ISO7816.OFFSET_INS], p1 = buf[ISO7816.OFFSET_P1], p2 = buf[ISO7816.OFFSET_P2];
            short len = apdu.setIncomingAndReceive();
            for (short i = 0; i < len; i++) {
                NvmLedger.store(buf);
                buf[i] = buf[(short) (ISO7816.OFFSET_CDATA + i)];
            }
            byte[] resp = output == 1 ? persistentSpan : output == 3 ? transientSpan : buf;
            byte[] work = output == 2 ? persistentSpan : buf;
            short out = logic.dispatchStreamTo(ins, p1, p2, buf, (short) 0, len, resp, (short) 0, (short) 255,
                    work, (short) 0, (short) work.length, authenticated);
            if (out > 0 && resp != buf) {
                for (short i = 0; i < out; i++) {
                    NvmLedger.store(buf);
                    buf[i] = resp[i];
                }
            }
            if (out > 0) apdu.setOutgoingAndSend((short) 0, out);
            return;
        }
        short n = logic.dispatchTo(buf[ISO7816.OFFSET_INS], buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2],
                noData, (short) 0, (short) 0, buf, (short) 0, (short) buf.length, buf, (short) 0, (short) buf.length);
        apdu.setOutgoingAndSend((short) 0, n);
    }

    static final class Logic extends Rev4ShapeSkeleton {
        // Transcript: tag 0x54, u16 body length, body. Parser state is RAM:
        // [0] header bytes seen, [1] declared body length, [2] body bytes seen.
        static final byte TRANSCRIPT_TAG = (byte) 0x54;
        static final short CERT_ADM_CAPACITY = 1335;
        final short[] parser = JCSystem.makeTransientShortArray((short) 3, JCSystem.CLEAR_ON_RESET);
        final KeyPair keys = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        final Signature signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        // Admission result state held between CLOSE_WRITE and the reads: the
        // 73 B signature record, in RAM, as a randomized ECDSA signature must be.
        final byte[] admissionSignature = JCSystem.makeTransientByteArray((short) 73, JCSystem.CLEAR_ON_RESET);
        // Cert_adm evidence: a persistent record written once at install, as the
        // Auth 0x0011 record is; producers only read it.
        final byte[] certAdm = new byte[CERT_ADM_CAPACITY];

        Logic() {
            super(null);
            keys.genKeyPair();
            for (short i = 0; i < CERT_ADM_CAPACITY; i++) {
                certAdm[i] = (byte) (0x30 + i * 13);
            }
        }

        protected byte onGetVersion(byte[] w, short wo, short wc) {
            return 1;
        }

        // --- chunked signature (INS 0x20) ------------------------------------

        protected void onSignTranscriptChunk(short packetIndex, short packetCount,
                byte[] chunk, short chunkOffset, short chunkLength, byte[] w, short wo, short wc) {
            consumeTranscript(packetIndex, chunk, chunkOffset, chunkLength);
        }

        protected short onSignTranscriptFinish(short inputLength, byte[] output, short outputOffset, short outputCapacity,
                byte[] w, short wo, short wc) {
            finishCalls++;
            requireWholeTranscript(inputLength);
            short length = signer.sign(output, outputOffset, (short) 0, output, (short) (outputOffset + 1));
            // The native signer wrote length bytes into output.
            for (short i = 0; i < length; i++) {
                NvmLedger.store(output);
            }
            NvmLedger.store(output);
            output[outputOffset] = (byte) length;
            for (short i = (short) (length + 1); i < 73; i++) {
                NvmLedger.store(output);
                output[(short) (outputOffset + i)] = 0;
            }
            if (control == 1) failStream((short) 0x6985);
            return control == 2 ? (short) 74 : (short) 73;
        }

        /** Incremental transcript parser feeding Signature.update; RAM state only. */
        private void consumeTranscript(short packetIndex, byte[] chunk, short chunkOffset, short chunkLength) {
            chunkCalls++;
            if (chunkLength > maxChunk) maxChunk = chunkLength;
            if (JCSystem.isTransient(chunk) == JCSystem.NOT_A_TRANSIENT_OBJECT && chunk != NvmLedger.apdu) {
                chunkFromPersistent = true;
            }
            if (packetIndex == 0) {
                if (control == 4) failStream((short) 0x6A88);
                NvmLedger.store(parser);
                parser[0] = 0;
                NvmLedger.store(parser);
                parser[1] = 0;
                NvmLedger.store(parser);
                parser[2] = 0;
                signer.init(keys.getPrivate(), Signature.MODE_SIGN);
            }
            if (control == 3 && packetIndex == 1) failStream((short) 0x6F00);
            for (short i = 0; i < chunkLength; i++) {
                byte value = chunk[(short) (chunkOffset + i)];
                if (parser[0] == 0) {
                    if (value != TRANSCRIPT_TAG) failStream((short) 0x6A80);
                    NvmLedger.store(parser);
                    parser[0] = 1;
                } else if (parser[0] < 3) {
                    NvmLedger.store(parser);
                    parser[1] = (short) ((parser[1] << 8) | (value & 0xFF));
                    NvmLedger.store(parser);
                    parser[0]++;
                } else {
                    NvmLedger.store(parser);
                    parser[2]++;
                }
            }
            signer.update(chunk, chunkOffset, chunkLength);
        }

        private void requireWholeTranscript(short inputLength) {
            if (parser[0] != 3 || parser[2] != parser[1] || (short) (parser[2] + 3) != inputLength) {
                failStream((short) 0x6A80);
            }
        }

        // --- authenticated issuer upload ----------------------------------------

        protected short onPutLeafStream(byte[] input, short io, short il, byte[] output, short oo, short oc,
                byte[] w, short wo, short wc) {
            stagedCalls++;
            for (short i = 0; i < 16; i++) {
                NvmLedger.store(w);
                w[(short) (wo + i)] = (byte) 0x5A;
            }
            for (short i = 0; i < 36; i++) {
                NvmLedger.store(output);
                output[(short) (oo + i)] = (byte) (input[(short) (io + (i % il))] ^ i ^ 36);
            }
            return 36;
        }

        // --- public streamed result (option A, INS 0x10) -------------------------

        protected short onBuildEnvelopePrepare(byte[] input, short io, short il, byte[] w, short wo, short wc) {
            prepareCalls++;
            produceCalls = 0;
            if (control == 5) failStream((short) 0x6A80);
            if (control == 6) return (short) 1793;
            if (control == 7) return (short) 0;
            if (control == 9) return (short) 1792;
            return il;
        }

        protected void onBuildEnvelopeProduce(byte[] input, short io, short il, short resultOffset,
                byte[] output, short oo, short length, byte[] w, short wo, short wc) {
            produce();
            for (short i = 0; i < length; i++) {
                short at = (short) (resultOffset + i);
                byte value = (byte) (input[(short) (io + (short) (at % il))] ^ 0x5A ^ at);
                // A drifting producer returns different bytes on reads.
                if (control == 8 && produceCalls > driftAfter) value = (byte) ~value;
                NvmLedger.store(output);
                output[(short) (oo + i)] = value;
            }
        }

        // --- chunked admission with a streamed result (INS 0x70) ---------------

        protected void onSignAdmissionChunk(short packetIndex, short packetCount,
                byte[] chunk, short chunkOffset, short chunkLength, byte[] w, short wo, short wc) {
            consumeTranscript(packetIndex, chunk, chunkOffset, chunkLength);
        }

        protected short onSignAdmissionPrepare(short inputLength, byte[] w, short wo, short wc) {
            prepareCalls++;
            produceCalls = 0;
            if (control == 5) failStream((short) 0x6A80);
            requireWholeTranscript(inputLength);
            // The 73 B signature record is the only result state; it stays in RAM.
            short length = signer.sign(admissionSignature, (short) 0, (short) 0, admissionSignature, (short) 1);
            for (short i = 0; i < length; i++) {
                NvmLedger.store(admissionSignature);
            }
            NvmLedger.store(admissionSignature);
            admissionSignature[0] = (byte) length;
            for (short i = (short) (length + 1); i < 73; i++) {
                NvmLedger.store(admissionSignature);
                admissionSignature[i] = 0;
            }
            if (control == 6) return (short) 1409;
            if (control == 7) return (short) 0;
            return (short) (73 + (control == 9 ? (short) CERT_ADM_CAPACITY : certLength));
        }

        protected void onSignAdmissionProduce(short resultOffset, byte[] output, short oo, short length,
                byte[] w, short wo, short wc) {
            produce();
            for (short i = 0; i < length; i++) {
                short at = (short) (resultOffset + i);
                // Signature from RAM, then Cert_adm read straight from its
                // persistent record: no staging copy of either.
                byte value = at < 73 ? admissionSignature[at] : certAdm[(short) (at - 73)];
                if (control == 8 && produceCalls > driftAfter) value = (byte) ~value;
                NvmLedger.store(output);
                output[(short) (oo + i)] = value;
            }
        }

        private void produce() {
            produceCalls++;
            if (failProduceAt != 0 && produceCalls == failProduceAt) failStream((short) 0x6F00);
        }
    }
}

final class NvmLedger {
    static byte[] apdu;
    static int persistent, transientStores, apduStores;

    static void store(Object array) {
        if (array == null) return;
        if (array == apdu) {
            apduStores++;
            return;
        }
        if (JCSystem.isTransient(array) != JCSystem.NOT_A_TRANSIENT_OBJECT) {
            transientStores++;
            return;
        }
        persistent++;
    }

    static void reset() {
        persistent = transientStores = apduStores = 0;
    }
}
