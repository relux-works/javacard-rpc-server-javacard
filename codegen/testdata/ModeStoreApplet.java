package io.jcrpc.modestore.server;

import javacard.framework.*;
import javacard.security.MessageDigest;

/**
 * Independent storage fixture: inspect relative u16 seeks, read a circular
 * window, describe an authenticated page, and preview a reversed page.
 * Every array element store is reported to NvmLedger by array identity.
 * Native MessageDigest state and physical EEPROM are outside that ledger.
 */
public final class ModeStoreApplet extends Applet {
    static ModeStoreApplet installed;
    static boolean authenticated = true, direct = false;
    // 0 accept; 1 finish fails after writing output; 2 finish returns 7;
    // 3 chunk handler fails on packet 1; 4 store unavailable; 5 prepare fails;
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
    // Storage window length and the producer call after which a drifting
    // producer changes its bytes.
    static short windowLength = 600;
    static int driftAfter = 8;

    final Logic logic = new Logic();
    final ModeStoreStreamAPDUAdapter adapter = new ModeStoreStreamAPDUAdapter(logic);
    final byte[] noData = new byte[0];
    final byte[] persistentSpan = new byte[255];
    final byte[] transientSpan = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);

    public static void install(byte[] b, short o, byte l) {
        new ModeStoreApplet().register();
    }

    ModeStoreApplet() {
        installed = this;
    }

    public void deselect() {
        adapter.deselect();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buf = apdu.getBuffer();
        NvmLedger.apdu = buf;
        // Test-only ordinary entry: the applet invalidates public authority outside dispatch.
        if (buf[ISO7816.OFFSET_INS] == (byte) 0x02) {
            logic.abortPublicStreams(ModeStoreStreamEndpoint.ABORT_HOST_FAILURE);
            return;
        }
        if (logic.isStreamInstruction(buf[ISO7816.OFFSET_INS])) {
            if (!direct) {
                adapter.processIfStream(apdu, authenticated);
                return;
            }
            // direct route: one APDU buffer is request, response and caller workspace.
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

    static final class Logic extends ModeStoreSkeleton {
        // A circular read-only store and a RAM-only reducer of u16 relative seeks.
        // State: byte count, cursor, word XOR, pending high byte.
        static final short STORE_CAPACITY = 1280;
        final short[] seeks = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_RESET);
        final byte[] storedBytes = new byte[STORE_CAPACITY];
        final MessageDigest pageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        Logic() {
            super(null);
            for (short i = 0; i < STORE_CAPACITY; i++) storedBytes[i] = (byte) (i / 16 + i % 16);
        }

        protected byte onGetVersion(byte[] w, short wo, short wc) { return 1; }

        protected void onInspectOffsetsChunk(short packetIndex, short packetCount,
                byte[] chunk, short chunkOffset, short chunkLength, byte[] w, short wo, short wc) {
            consumeSeeks(packetIndex, chunk, chunkOffset, chunkLength);
        }

        protected short onInspectOffsetsFinish(short inputLength, byte[] output, short oo, short oc,
                byte[] w, short wo, short wc) {
            finishCalls++;
            requireCompleteSeeks(inputLength);
            putShort(output, oo, (short) (inputLength / 2));
            putShort(output, (short) (oo + 2), seeks[1]);
            putShort(output, (short) (oo + 4), seeks[2]);
            if (control == 1) failStream((short) 0x6985);
            return control == 2 ? (short) 7 : (short) 6;
        }

        private void consumeSeeks(short packetIndex, byte[] chunk, short co, short length) {
            chunkCalls++;
            if (length > maxChunk) maxChunk = length;
            if (JCSystem.isTransient(chunk) == JCSystem.NOT_A_TRANSIENT_OBJECT && chunk != NvmLedger.apdu) {
                chunkFromPersistent = true;
            }
            if (packetIndex == 0) {
                if (control == 4) failStream((short) 0x6A88);
                for (short i = 0; i < 4; i++) {
                    NvmLedger.store(seeks);
                    seeks[i] = 0;
                }
            }
            if (control == 3 && packetIndex == 1) failStream((short) 0x6F00);
            for (short i = 0; i < length; i++) {
                short value = (short) (chunk[(short) (co + i)] & 255);
                if ((seeks[0] & 1) == 0) {
                    NvmLedger.store(seeks);
                    seeks[3] = value;
                } else {
                    short word = (short) ((seeks[3] << 8) | value);
                    if (word == (short) 0xFFFF) failStream((short) 0x6A80);
                    // Reduce each part before addition to stay within signed short.
                    // 1280 = 5 * 256; reduce the high byte before multiplying.
                    short advance = (short) (((seeks[3] % 5) * 256 + value) % STORE_CAPACITY);
                    NvmLedger.store(seeks);
                    seeks[1] = (short) ((seeks[1] + advance) % STORE_CAPACITY);
                    NvmLedger.store(seeks);
                    seeks[2] ^= word;
                }
                NvmLedger.store(seeks);
                seeks[0]++;
            }
        }

        private void requireCompleteSeeks(short inputLength) {
            if (inputLength == 0 || seeks[0] != inputLength || (inputLength & 1) != 0) {
                failStream((short) 0x6A80);
            }
        }

        private void putShort(byte[] output, short at, short value) {
            NvmLedger.store(output);
            output[at] = (byte) (value >> 8);
            NvmLedger.store(output);
            output[(short) (at + 1)] = (byte) value;
        }

        // Authenticated input stays in the runtime workspace; describe it in RAM.
        protected short onDescribePageStream(byte[] input, short io, short il, byte[] output, short oo, short oc,
                byte[] w, short wo, short wc) {
            stagedCalls++;
            for (short i = 0; i < 16; i++) {
                NvmLedger.store(w);
                w[(short) (wo + i)] = (byte) 0x5A;
            }
            putShort(output, oo, (short) 0);
            putShort(output, (short) (oo + 2), il);
            pageDigest.doFinal(input, io, il, output, (short) (oo + 4));
            for (short i = 0; i < 32; i++) NvmLedger.store(output);
            return 36;
        }

        protected short onExchangePagePrepare(byte[] input, short io, short il, byte[] w, short wo, short wc) {
            prepareCalls++;
            produceCalls = 0;
            if (control == 5) failStream((short) 0x6A80);
            if (control == 6) return (short) 1473;
            if (control == 7) return (short) 0;
            if (control == 9) return (short) 1472;
            return il;
        }

        // Preview a page in reverse order, repeating only for the max-result control.
        protected void onExchangePageProduce(byte[] input, short io, short il, short resultOffset,
                byte[] output, short oo, short length, byte[] w, short wo, short wc) {
            produce();
            for (short i = 0; i < length; i++) {
                short at = (short) (resultOffset + i);
                byte value = input[(short) (io + il - 1 - (short) (at % il))];
                if (control == 8 && produceCalls > driftAfter) value = (byte) ~value;
                NvmLedger.store(output);
                output[(short) (oo + i)] = value;
            }
        }

        protected void onReadWindowChunk(short packetIndex, short packetCount,
                byte[] chunk, short chunkOffset, short chunkLength, byte[] w, short wo, short wc) {
            consumeSeeks(packetIndex, chunk, chunkOffset, chunkLength);
        }

        protected short onReadWindowPrepare(short inputLength, byte[] w, short wo, short wc) {
            prepareCalls++;
            produceCalls = 0;
            if (control == 5) failStream((short) 0x6A80);
            requireCompleteSeeks(inputLength);
            if (control == 6) return (short) 1281;
            if (control == 7) return (short) 0;
            return control == 9 ? STORE_CAPACITY : windowLength;
        }

        // No prefix or proof: just a circular window read from persistent storage.
        protected void onReadWindowProduce(short resultOffset, byte[] output, short oo, short length,
                byte[] w, short wo, short wc) {
            produce();
            for (short i = 0; i < length; i++) {
                short at = (short) ((seeks[1] + resultOffset + i) % STORE_CAPACITY);
                byte value = storedBytes[at];
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
