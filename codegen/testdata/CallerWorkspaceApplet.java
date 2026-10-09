package io.jcrpc.workspace;

import javacard.framework.*;

/** Actual process/send fixture: all borrowed arrays stay on this stack. */
public final class CallerWorkspaceApplet extends Applet {
    private final CallerWorkspaceLogic logic = new CallerWorkspaceLogic();
    private final WorkspaceDemoStreamAPDUAdapter streams = new WorkspaceDemoStreamAPDUAdapter(logic);

    public static void install(byte[] b, short offset, byte length) {
        new CallerWorkspaceApplet().register();
    }
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        if (streams.processIfStream(apdu)) return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        short received = apdu.setIncomingAndReceive();
        short length = apdu.getIncomingLength();
        short offset = apdu.getOffsetCdata();
        while (received < length) {
            short next = apdu.receiveBytes((short) (offset + received));
            if (next == 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            received += next;
        }
        // Controlled phases/refusals exercise an explicitly smaller legal span.
        logic.required = p1 == (byte) 2 ? (short) 260 : (short) 196;
        short scratchCapacity = p1 == (byte) 1 ? (short) 133 : (short) (buffer.length - 11);
        logic.forcedProduced = p2 == (byte) 1 ? (short) 126 : (short) -2;
        try {
            short produced = logic.dispatchTo(ins, p1, p2,
                    buffer, offset, length, buffer, (short) 7, (short) (buffer.length - 7),
                    buffer, (short) 11, scratchCapacity);
            if (produced > 0) {
                apdu.setOutgoing();
                apdu.setOutgoingLength(produced);
                apdu.sendBytesLong(buffer, (short) 7, produced);
            }
        } catch (WorkspaceDemoSkeleton.StatusWordException failure) {
            ISOException.throwIt(failure.getStatusWord());
        }
    }
    public void deselect() { streams.deselect(); }
}
