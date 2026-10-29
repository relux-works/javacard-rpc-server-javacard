package io.jcrpc.modestore.server;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.security.MessageDigest;

/** Converter fixture: every per-method mode callback with Java Card Classic APIs. */
public final class ModeStoreCAPApplet extends Applet {
    private final Logic logic;
    private final ModeStoreStreamAPDUAdapter streams;
    private final byte[] noData;
    private boolean authenticated;

    public static void install(byte[] installData, short offset, byte length) {
        new ModeStoreCAPApplet().register();
    }

    ModeStoreCAPApplet() {
        logic = new Logic();
        streams = new ModeStoreStreamAPDUAdapter(logic);
        noData = new byte[0];
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        if (ins >= (byte) 0x23 && ins <= (byte) 0x28) {
            // One borrowed APDU buffer supplies request, response and scratch.
            byte p1 = buffer[ISO7816.OFFSET_P1];
            byte p2 = buffer[ISO7816.OFFSET_P2];
            short length = apdu.setIncomingAndReceive();
            for (short i = 0; i < length; i++) {
                buffer[i] = buffer[(short) (ISO7816.OFFSET_CDATA + i)];
            }
            short produced = logic.dispatchStreamTo(ins, p1, p2, buffer, (short) 0, length,
                    buffer, (short) 0, (short) 255, buffer, (short) 0, (short) buffer.length, authenticated);
            if (produced > 0) apdu.setOutgoingAndSend((short) 0, produced);
            return;
        }
        if (streams.processIfStream(apdu, authenticated)) return;
        short produced = logic.dispatchTo(ins, buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2],
                noData, (short) 0, (short) 0, buffer, (short) 0, (short) buffer.length, buffer, (short) 0, (short) buffer.length);
        apdu.setOutgoingAndSend((short) 0, produced);
    }

    public void deselect() {
        streams.deselect();
    }

    private static final class Logic extends ModeStoreSkeleton {
        private final short[] seeks;
        private final byte[] storedBytes;
        private final MessageDigest pageDigest;

        Logic() {
            super(null);
            seeks = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_RESET);
            storedBytes = new byte[(short) 1280];
            for (short i = 0; i < (short) 1280; i++) storedBytes[i] = (byte) (i / 16 + i % 16);
            pageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }

        protected byte onGetVersion(byte[] w, short wo, short wc) { return (byte) 1; }

        // Big-endian relative seeks; FFFF is reserved and a partial word is invalid.
        protected void onInspectOffsetsChunk(short index, short count, byte[] input, short io,
                short length, byte[] w, short wo, short wc) {
            if (index == 0) for (short j = 0; j < 4; j++) seeks[j] = 0;
            for (short j = 0; j < length; j++) {
                short value = (short) (input[(short) (io + j)] & 255);
                if ((seeks[0] & 1) == 0) {
                    seeks[3] = value;
                } else {
                    short word = (short) ((seeks[3] << 8) | value);
                    if (word == (short) 0xFFFF) failStream((short) 0x6A80);
                    short advance = (short) ((seeks[3] % 5) * 256 + value);
                    seeks[1] = (short) ((seeks[1] + advance) % 1280);
                    seeks[2] ^= word;
                }
                seeks[0]++;
            }
        }

        private void complete(short length) {
            if (length == 0 || length != seeks[0] || (length & 1) != 0) failStream((short) 0x6A80);
        }

        private void putShort(byte[] output, short offset, short value) {
            output[offset] = (byte) (value >> 8);
            output[(short) (offset + 1)] = (byte) value;
        }

        protected short onInspectOffsetsFinish(short length, byte[] output, short oo, short oc,
                byte[] w, short wo, short wc) {
            complete(length);
            putShort(output, oo, (short) (length / 2));
            putShort(output, (short) (oo + 2), seeks[1]);
            putShort(output, (short) (oo + 4), seeks[2]);
            return (short) 6;
        }

        protected short onDescribePageStream(byte[] input, short io, short length, byte[] output,
                short oo, short oc, byte[] w, short wo, short wc) {
            putShort(output, oo, (short) 0);
            putShort(output, (short) (oo + 2), length);
            pageDigest.doFinal(input, io, length, output, (short) (oo + 4));
            return (short) 36;
        }

        // The public mode uses the same short-result handler as the simulator fixture.
        protected short onDescribePublicPageStream(byte[] input, short io, short length, byte[] output,
                short oo, short oc, byte[] w, short wo, short wc) {
            return onDescribePageStream(input, io, length, output, oo, oc, w, wo, wc);
        }

        protected short onExchangePagePrepare(byte[] input, short io, short length,
                byte[] w, short wo, short wc) {
            return length;
        }

        protected void onExchangePageProduce(byte[] input, short io, short length, short offset,
                byte[] output, short oo, short width, byte[] w, short wo, short wc) {
            for (short j = 0; j < width; j++) {
                output[(short) (oo + j)] = input[(short) (io + length - 1 - (short) ((offset + j) % length))];
            }
        }

        protected void onReadWindowChunk(short index, short count, byte[] input, short io,
                short length, byte[] w, short wo, short wc) {
            onInspectOffsetsChunk(index, count, input, io, length, w, wo, wc);
        }

        protected short onReadWindowPrepare(short length, byte[] w, short wo, short wc) {
            complete(length);
            return (short) 600;
        }

        protected void onReadWindowProduce(short offset, byte[] output, short oo, short width,
                byte[] w, short wo, short wc) {
            for (short j = 0; j < width; j++) {
                output[(short) (oo + j)] = storedBytes[(short) ((seeks[1] + offset + j) % 1280)];
            }
        }
    }
}
