package io.jcrpc.workspace;

/** Trusted business fixture: consumes live input before borrowing scratch, then
 * encodes output last. 196/260-byte minima are fixture phases, never RPC policy.
 * No borrowed buffer is stored in this object. Numeric counters expose effects.
 */
public class CallerWorkspaceLogic extends WorkspaceDemoSkeleton {
    public short calls;
    public short effects;
    public short required = (short) 196;
    public short forcedProduced = (short) -2;

    public CallerWorkspaceLogic() { super(null); }

    protected void probeWorkspace(byte[] scratch, short offset, short capacity) {
        calls++;
        if (capacity < required) throw statusWordFailure((short) 0x6A84);
        // Phase scratch is inside its declared window; no per-command allocation.
        if (capacity > 0) {
            scratch[offset] = (byte) 0x45;
            scratch[(short) (offset + capacity - 1)] = (byte) 0x54;
        }
        effects++;
    }

    private short reply(byte[] output, short offset, short capacity, byte marker) {
        for (short i = 0; i < capacity; i++) output[(short) (offset + i)] = marker;
        return forcedProduced == (short) -2 ? capacity : forcedProduced;
    }

    protected short onIdentity(byte[] output, short offset, short capacity,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        return reply(output, offset, capacity, (byte) 1);
    }
    protected short onPacked(byte[] output, short offset, short capacity,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        return reply(output, offset, capacity, (byte) 2);
    }
    protected short onIssuer(byte[] output, short offset, short capacity,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        return reply(output, offset, capacity, (byte) 3);
    }
    protected short onScalar(byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        return (short) 0x1234;
    }
    protected void onConsume(byte[] payload, short payloadOffset, short payloadLength,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        // The third byte is the last consumer: don't overwrite aliased scratch yet.
        if (payloadLength != 3 || payload[payloadOffset] != 11 ||
                payload[(short) (payloadOffset + 1)] != 22 ||
                payload[(short) (payloadOffset + 2)] != 33) {
            throw statusWordFailure((short) 0x6A80);
        }
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
    }
    protected short onUploadStream(byte[] input, short inputOffset, short inputLength,
            byte[] output, short outputOffset, short outputCapacity,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        // Consume original input before any scratch or output write.
        if (inputLength != 3 || input[inputOffset] != 11 ||
                input[(short) (inputOffset + 1)] != 22 ||
                input[(short) (inputOffset + 2)] != 33) failStream((short) 0x6A80);
        if (callerWorkspaceCapacity < required) { calls++; failStream((short) 0x6A84); }
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        return reply(output, outputOffset, outputCapacity, (byte) 6);
    }
    protected short onDownloadStream(byte[] input, short inputOffset, short inputLength,
            byte[] output, short outputOffset, short outputCapacity,
            byte[] callerWorkspace, short callerWorkspaceOffset, short callerWorkspaceCapacity) {
        if (inputLength != 3 || input[inputOffset] != 11 ||
                input[(short) (inputOffset + 1)] != 22 ||
                input[(short) (inputOffset + 2)] != 33) failStream((short) 0x6A80);
        if (callerWorkspaceCapacity < required) { calls++; failStream((short) 0x6A84); }
        probeWorkspace(callerWorkspace, callerWorkspaceOffset, callerWorkspaceCapacity);
        // Produced stream stays session-owned, independent of caller scratch.
        for (short i = 0; i < 127; i++) output[(short) (outputOffset + i)] = (byte) 7;
        return forcedProduced == (short) -2 ? (short) 127 : forcedProduced;
    }
}
