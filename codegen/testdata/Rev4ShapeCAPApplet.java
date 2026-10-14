package io.jcrpc.rev4shape.server;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

/** Converter fixture: every per-method mode callback with Java Card Classic APIs. */
public final class Rev4ShapeCAPApplet extends Applet {
    private final Logic logic;
    private final Rev4ShapeStreamAPDUAdapter streams;
    private final byte[] noData;
    private boolean authenticated;

    public static void install(byte[] installData, short offset, byte length) {
        new Rev4ShapeCAPApplet().register();
    }

    Rev4ShapeCAPApplet() {
        logic = new Logic();
        streams = new Rev4ShapeStreamAPDUAdapter(logic);
        noData = new byte[0];
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        if (ins >= (byte) 0x20 && ins <= (byte) 0x25) {
            // Auth-shaped route: one APDU buffer for request, response and scratch.
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

    private static final class Logic extends Rev4ShapeSkeleton {
        private final KeyPair keys;
        private final Signature signer;
        private final short[] parser;

        Logic() {
            super(null);
            keys = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            parser = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        }

        protected byte onGetVersion(byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            return (byte) 1;
        }

        protected void onSignTranscriptChunk(short packetIndex, short packetCount, byte[] chunk, short chunkOffset,
                short chunkLength, byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            if (packetIndex == 0) {
                parser[0] = 0;
                signer.init(keys.getPrivate(), Signature.MODE_SIGN);
            }
            parser[0] = (short) (parser[0] + chunkLength);
            signer.update(chunk, chunkOffset, chunkLength);
        }

        protected short onSignTranscriptFinish(short inputLength, byte[] output, short outputOffset, short outputCapacity,
                byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            if (parser[0] != inputLength) failStream((short) 0x6A80);
            short length = signer.sign(output, outputOffset, (short) 0, output, (short) (outputOffset + 1));
            output[outputOffset] = (byte) length;
            for (short i = (short) (length + 1); i < (short) 73; i++) {
                output[(short) (outputOffset + i)] = 0;
            }
            return (short) 73;
        }

        protected short onPutLeafStream(byte[] input, short inputOffset, short inputLength, byte[] output,
                short outputOffset, short outputCapacity, byte[] callerWorkspace, short callerWorkspaceOffset,
                short callerWorkspaceCapacity) {
            return fill(input, inputOffset, inputLength, (short) 0, output, outputOffset, (short) 36);
        }

        protected short onBuildEnvelopePrepare(byte[] input, short inputOffset, short inputLength,
                byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            return inputLength;
        }

        protected void onBuildEnvelopeProduce(byte[] input, short inputOffset, short inputLength, short resultOffset,
                byte[] output, short outputOffset, short length, byte[] callerWorkspace, short callerWorkspaceOffset,
                short callerWorkspaceCapacity) {
            fill(input, inputOffset, inputLength, resultOffset, output, outputOffset, length);
        }

        protected short onSignAdmissionPrepare(byte[] input, short inputOffset, short inputLength,
                byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
            return (short) (inputLength + 73);
        }

        protected void onSignAdmissionProduce(byte[] input, short inputOffset, short inputLength, short resultOffset,
                byte[] output, short outputOffset, short length, byte[] callerWorkspace, short callerWorkspaceOffset,
                short callerWorkspaceCapacity) {
            fill(input, inputOffset, inputLength, resultOffset, output, outputOffset, length);
        }

        private short fill(byte[] input, short inputOffset, short inputLength, short resultOffset,
                byte[] output, short outputOffset, short width) {
            for (short i = 0; i < width; i++) {
                short at = (short) (resultOffset + i);
                output[(short) (outputOffset + i)] = input[(short) (inputOffset + (short) (at % inputLength))];
            }
            return width;
        }
    }
}
