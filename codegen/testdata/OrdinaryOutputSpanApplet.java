package io.jcrpc.writer;

import javacard.framework.*;

/** CAP-compatible caller fixture. APDU and its buffer remain command-local.
 * P1 injects a wrong fixed produced length solely for refusal/send witnesses.
 */
public final class OrdinaryOutputSpanApplet extends Applet {
    private final Logic logic = new Logic();

    public static void install(byte[] b, short off, byte len) {
        new OrdinaryOutputSpanApplet().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short received = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        short requestOffset = apdu.getOffsetCdata();
        while (received < length) {
            short next = apdu.receiveBytes((short) (requestOffset + received));
            if (next == 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            received += next;
        }
        short outputOffset = ins == (byte) 1 ? (short) 6 : (short) 7;
        logic.forced = p1;
        try {
            short produced = logic.dispatchTo(ins, p1, p2,
                    buffer, requestOffset, length,
                    buffer, outputOffset, (short) (buffer.length - outputOffset));
            if (produced > 0) {
                apdu.setOutgoing();
                apdu.setOutgoingLength(produced);
                apdu.sendBytesLong(buffer, outputOffset, produced);
            }
        } catch (WriterDemoSkeleton.StatusWordException e) {
            ISOException.throwIt(e.getStatusWord());
        }
    }

    private static final class Logic extends WriterDemoSkeleton {
        byte forced;
        Logic() { super(null); }
        private short fill(byte[] out, short off, short cap, byte ins) {
            for (short i = 0; i < cap; i++) out[(short) (off + i)] = (byte) (i + ins);
            if (forced == (byte) 1) return (short) (cap - 1);
            if (forced == (byte) 2) return (short) -1;
            if (forced == (byte) 3) return (short) (cap + 1);
            return cap;
        }
        protected short onGetAuthenticationIdentity(byte[] out, short off, short cap) { return fill(out, off, cap, (byte) 1); }
        protected short onGetAuthAppletInfo(byte[] out, short off, short cap) { return fill(out, off, cap, (byte) 2); }
        protected short onGetIssuer190(byte[] out, short off, short cap) { return fill(out, off, cap, (byte) 3); }
        protected short onGetIssuer177(byte[] out, short off, short cap) { return fill(out, off, cap, (byte) 4); }
        protected byte onScalar0() { return (byte) 0xFE; }
        protected boolean onScalar1() { return true; }
        protected short onScalar2() { return (short) 0x1234; }
        protected int onScalar3() { return 0x01020304; }
        protected void onClear() {}
        protected int onTyped(short first, int second) { return second ^ (first & 0xFFFF); }
        protected short onEcho(short prefix, byte[] payload, short payloadOffset, short payloadLength,
                byte[] out, short off, short cap) {
            if (prefix != payloadLength || payloadLength > cap) throw statusWordFailure(ISO7816.SW_WRONG_LENGTH);
            packBytes(out, off, payload, payloadOffset, payloadLength);
            return payloadLength;
        }
    }
}
