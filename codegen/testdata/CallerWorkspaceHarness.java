package io.jcrpc.workspace;

import javacard.framework.*;
import java.util.Arrays;
import java.lang.reflect.*;
import java.security.MessageDigest;
import com.licel.jcardsim.base.Simulator;

/** Direct production entry-point witnesses. Oracle references belong only to
 * this host test subclass, never to generated source or the CAP business fixture.
 */
public final class CallerWorkspaceHarness {
    static final byte SENTINEL = (byte) 0x5A;
    static final byte[] INPUT = {11, 22, 33};
    static final class Logic extends CallerWorkspaceLogic {
        byte[] expected;
        short expectedOffset, expectedCapacity;
        void expect(byte[] buffer, int offset, int capacity) {
            expected = buffer; expectedOffset = (short) offset; expectedCapacity = (short) capacity;
        }
        protected void probeWorkspace(byte[] buffer, short offset, short capacity) {
            require(buffer == expected && offset == expectedOffset && capacity == expectedCapacity,
                    "testExactWorkspaceIdentity");
            // Catch an admitted invalid span at the callback boundary before a
            // bad pointer can turn a gate failure into an unrelated JVM crash.
            require(buffer != null && offset >= 0 && capacity >= 0 && offset <= buffer.length &&
                    capacity <= buffer.length - offset, "testWorkspaceBeforeEffects");
            super.probeWorkspace(buffer, offset, capacity);
        }
    }
    interface Action { void run(); }
    static void require(boolean condition, String claim) {
        if (!condition) throw new AssertionError(claim);
    }
    static byte[] filled(int size) { byte[] b = new byte[size]; Arrays.fill(b, SENTINEL); return b; }
    static void refuse(int status, Action action, String claim) {
        try { action.run(); throw new AssertionError(claim + " admitted"); }
        catch (WorkspaceDemoSkeleton.StatusWordException e) { require((e.getStatusWord() & 65535) == status, claim + " status"); }
        catch (ISOException e) { require((e.getReason() & 65535) == status, claim + " status"); }
    }
    static short ordinary(Logic logic, int ins, byte[] input, int inputOffset, int inputLength,
            byte[] output, int outputOffset, int outputCapacity, byte[] scratch, int offset, int capacity) {
        logic.expect(scratch, offset, capacity);
        return logic.dispatchTo((byte) ins, (byte) 0, (byte) 0, input, (short) inputOffset, (short) inputLength,
                output, (short) outputOffset, (short) outputCapacity, scratch, (short) offset, (short) capacity);
    }
    static short stream(Logic logic, int ins, int p1, int p2, byte[] input, int inputOffset, int inputLength,
            byte[] output, int outputOffset, int outputCapacity, byte[] scratch, int offset, int capacity) {
        logic.expect(scratch, offset, capacity);
        return logic.dispatchStreamTo((byte) ins, (byte) p1, (byte) p2, input, (short) inputOffset, (short) inputLength,
                output, (short) outputOffset, (short) outputCapacity, scratch, (short) offset, (short) capacity);
    }
    static byte[] closeData(byte[] input) throws Exception {
        byte[] result = new byte[34]; result[0] = (byte) (input.length >>> 8); result[1] = (byte) input.length;
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(input);
        System.arraycopy(hash, 0, result, 2, 32); return result;
    }
    static void outside(byte[] b, int off, int len, String claim) {
        for (int i = 0; i < b.length; i++) if (i < off || i >= off + len) require(b[i] == SENTINEL, claim);
    }
    static void reply(byte[] b, int off, int len, int marker, String claim) {
        for (int i = 0; i < len; i++) require(b[off + i] == (byte) marker, claim);
    }
    static Object field(Object value, String name) throws Exception {
        for (Class<?> c = value.getClass(); c != null; c = c.getSuperclass()) {
            try { Field f = c.getDeclaredField(name); f.setAccessible(true); return f.get(value); }
            catch (NoSuchFieldException e) { }
        }
        throw new AssertionError("missing field " + name);
    }
    static Object runtime(Logic l) throws Exception { return field(l, "streamSession"); }
    static byte[] bulk(Logic l) throws Exception { return (byte[]) field(runtime(l), "workspace"); }
    static void notRetained(Object owner, Class<?> first, byte[]... borrowed) throws Exception {
        for (Class<?> c = first; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType().isPrimitive()) continue;
                f.setAccessible(true); Object value = f.get(Modifier.isStatic(f.getModifiers()) ? null : owner);
                for (byte[] b : borrowed) require(value != b, "testNoBorrowedReferences");
                if (value instanceof Object[]) for (Object v : (Object[]) value)
                    for (byte[] b : borrowed) require(v != b, "testNoBorrowedReferences");
            }
        }
    }
    static void noBorrowed(Logic l, byte[]... borrowed) throws Exception {
        notRetained(l, WorkspaceDemoSkeleton.class, borrowed);
        Object rt = runtime(l); notRetained(rt, rt.getClass(), borrowed);
        // Business handler remains the sole allowed reference in the owned slot.
        Object[] slot = (Object[]) field(rt, "handlerSlot");
        require(slot[0] == null || slot[0] == l, "testNoBorrowedReferences");
    }
    static void prepareUpload(Logic l, byte[] scratch, int off, int cap) {
        byte[] out = filled(220);
        require(stream(l, 0x20, 0, 1, INPUT, 0, 3, out, 9, 177, scratch, off, cap) == 0, "upload start");
        require(l.calls == 0, "upload must defer callback");
    }

    // All ordinary return shapes see a separate exact nonzero scratch window;
    // fixed reply widths 127/190/177 do not grow to its 260-byte capacity.
    static void testOrdinaryDisjoint() throws Exception {
        for (int ins = 1; ins <= 5; ins++) {
            Logic l = new Logic(); byte[] scratch = filled(300), out = filled(250), input = INPUT.clone();
            int n = ordinary(l, ins, ins == 5 ? input : null, 0, ins == 5 ? 3 : 0, out, 7, 220, scratch, 17, 260);
            int width = new int[]{0,127,190,177,2,0}[ins];
            require(n == width && l.calls == 1 && l.effects == 1, "testOrdinaryDisjoint");
            outside(out,7,width,"testExactOutputCapacity");outside(scratch,17,260,"testScratchSentinels");
            if (ins <= 3) reply(out,7,width,ins,"testExactOutputCapacity");
            if (ins == 4) require(out[7] == 0x12 && out[8] == 0x34,"testScalarEncoding");
            require(Arrays.equals(input,INPUT),"testInputLastConsumer"); noBorrowed(l,input,out,scratch);
        }
    }
    // Request/scratch overlap is legal when the trusted handler reads the last
    // byte first. Produced output is written last even when it overlaps scratch.
    static void testOverlapLiveness() throws Exception {
        Logic l = new Logic(); byte[] aliased = filled(300), out = filled(220);
        System.arraycopy(INPUT,0,aliased,17,3);
        ordinary(l,5,aliased,17,3,out,7,190,aliased,17,260);
        require(l.effects == 1 && aliased[17] == 0x45 && aliased[19] == 33,"testInputLastConsumer");
        l = new Logic(); aliased=filled(300);
        int n=ordinary(l,2,null,0,0,aliased,17,190,aliased,17,260);
        require(n==190,"testOverlapOutputLifetime");reply(aliased,17,190,2,"testOverlapOutputLifetime");outside(aliased,17,260,"testScratchSentinels");
        // Response-only input aliases entry scratch; session output is independent.
        l=new Logic();aliased=filled(300);System.arraycopy(INPUT,0,aliased,17,3);
        out=filled(80); n=stream(l,0x30,0,0,aliased,17,3,out,7,35,aliased,17,260);
        require(n==35 && l.effects==1,"testInputLastConsumer");
        // Deliberate callback input/output/scratch alias witness via reflection:
        // callers normally cannot acquire this private owned bulk array.
        l=new Logic();byte[] scratch=filled(300);prepareUpload(l,scratch,17,260);
        byte[] owned=bulk(l);byte[] close=closeData(INPUT);out=filled(220);
        n=stream(l,0x21,0,0,close,0,34,out,9,177,owned,0,260);
        require(n==177,"testInputLastConsumer");reply(out,9,177,6,"testOverlapOutputLifetime");
    }
    static void testStreamPathsAndLifetime() throws Exception {
        Logic l=new Logic();byte[] scratch=filled(300),out=filled(220);prepareUpload(l,scratch,17,260);
        byte[] close=closeData(INPUT);int n=stream(l,0x21,0,0,close,0,34,out,9,177,scratch,17,260);
        require(n==177 && l.calls==1,"testCloseWriteWorkspace");reply(out,9,177,6,"testExactOutputCapacity");outside(out,9,177,"testExactOutputCapacity");outside(scratch,17,260,"testScratchSentinels");
        noBorrowed(l,close,out,scratch);
        // CLOSE_WRITE replay uses stored receipt/output, with no second callback.
        Arrays.fill(scratch,(byte)0x38);Arrays.fill(out,SENTINEL);
        n=stream(l,0x21,0,0,close,0,34,out,9,177,scratch,17,260);
        require(n==177 && l.calls==1,"testCloseReplay");reply(out,9,177,6,"testCloseReplay");
        l=new Logic();scratch=filled(300);out=filled(80);byte[] input=INPUT.clone();
        n=stream(l,0x30,0,0,input,0,3,out,7,35,scratch,17,260);
        require(n==35 && l.calls==1 && out[7]==4 && out[8]==0 && out[9]==127,"testResponseOnlyWorkspace");outside(out,7,35,"testExactOutputCapacity");
        noBorrowed(l,input,out,scratch);Arrays.fill(scratch,(byte)0x71);
        byte[] result=new byte[127];int copied=0;
        for(int index=0;index<4;index++){
            byte[] read=filled(50);int size=stream(l,0x33,index,4,new byte[0],0,0,read,9,32,scratch,17,260);
            System.arraycopy(read,9,result,copied,size);outside(read,9,size,"testStreamReadLifetime");copied+=size;
        }
        require(copied==127 && l.calls==1,"testStreamReadLifetime");reply(result,0,127,7,"testStreamReadLifetime");
        byte[] receipt=closeData(result);
        stream(l,0x34,0,0,receipt,0,34,out,7,35,scratch,17,260);
        for(byte b:bulk(l))require(b==0,"testStreamCleanup");
        noBorrowed(l,input,out,scratch,receipt);
    }
    static final class BadSpan {
        final String name; final byte[] array; final int offset,capacity;
        BadSpan(String name,byte[] array,int offset,int capacity){this.name=name;this.array=array;this.offset=offset;this.capacity=capacity;}
    }
    static BadSpan[] badSpans() {
        return new BadSpan[]{new BadSpan("null",null,0,0),new BadSpan("negative-offset",filled(300),-1,260),
                new BadSpan("negative-capacity",filled(300),17,-1),new BadSpan("overflow",filled(300),32760,32760),
                new BadSpan("outside-offset",filled(300),301,0),new BadSpan("outside-end",filled(300),17,284),
                new BadSpan("end-nonzero",filled(300),300,1)};
    }
    // Every generic invalid scratch refuses before callbacks and writes. Unlike
    // protocol failure, a new invalid scratch must preserve a valid pending session.
    static void testWorkspaceBoundsAndRetry() throws Exception {
        for(BadSpan bad:badSpans()){
            Logic l=new Logic();byte[] out=filled(240);byte[] before=out.clone();final Logic ordinaryLogic=l;
            refuse(0x6700,()->ordinary(ordinaryLogic,1,null,0,0,out,7,190,bad.array,bad.offset,bad.capacity),"testWorkspaceBounds "+bad.name);
            require(l.calls==0 && l.effects==0 && Arrays.equals(out,before),"testWorkspaceBeforeEffects");
            if(bad.array!=null)outside(bad.array,0,0,"testWorkspaceBeforeEffects");
            byte[] valid=filled(300);require(ordinary(l,1,null,0,0,out,7,190,valid,17,260)==127,"testWorkspaceRetry");
            l=new Logic();prepareUpload(l,valid,17,260);final Logic streamLogic=l;byte[] close=closeData(INPUT);
            Object rt=runtime(l);short[] scalars=((short[])field(rt,"scalars")).clone();byte[] bulkBefore=bulk(l).clone();byte[] digest=((byte[])field(rt,"digestScratch")).clone();Object handler=((Object[])field(rt,"handlerSlot"))[0];
            Arrays.fill(out,SENTINEL);
            for(int ins:new int[]{0x21,0x22,0x25,0x30}){
                refuse(0x6700,()->stream(streamLogic,ins,0,0,close,0,34,out,7,190,bad.array,bad.offset,bad.capacity),"testWorkspaceBounds "+bad.name);
                require(l.calls==0 && l.effects==0 && Arrays.equals(out,before),"testWorkspaceBeforeEffects");
                require(Arrays.equals(scalars,(short[])field(rt,"scalars")) && Arrays.equals(bulkBefore,bulk(l)) && Arrays.equals(digest,(byte[])field(rt,"digestScratch")) && handler==((Object[])field(rt,"handlerSlot"))[0],"testInvalidScratchPreservesPending");
                noBorrowed(l,out,close,bad.array==null?new byte[0]:bad.array);
            }
            require(stream(l,0x21,0,0,close,0,34,out,7,190,valid,17,260)==177 && l.calls==1,"testWorkspaceRetry");
            // Invalid scratch while a response is live does not clear it either.
            l=new Logic();stream(l,0x30,0,0,INPUT,0,3,out,7,190,valid,17,260);final Logic readLogic=l;byte[] descriptor=Arrays.copyOfRange(out,7,42);
            refuse(0x6700,()->stream(readLogic,0x32,0,0,new byte[0],0,0,out,7,190,bad.array,bad.offset,bad.capacity),"testWorkspaceBounds "+bad.name);
            require(stream(l,0x32,0,0,new byte[0],0,0,out,7,190,valid,17,260)==35 && Arrays.equals(descriptor,Arrays.copyOfRange(out,7,42)) && l.calls==1,"testInvalidScratchPreservesPending");
            // Controlled post-reset state: real reset/deselect clearing is also
            // exercised by the retained native lifecycle tests. Here the marker
            // and transient state are explicitly cleared to isolate NVM effects.
            if (JCSystem.isTransient(bulk(streamLogic)) == JCSystem.NOT_A_TRANSIENT_OBJECT) {
                Arrays.fill((short[])field(rt,"scalars"),(short)0);
                Arrays.fill((Object[])field(rt,"handlerSlot"),null);
                Arrays.fill((byte[])field(rt,"digestScratch"),(byte)0);
                ((byte[])field(rt,"resetMarker"))[0]=0;
                Arrays.fill(bulk(streamLogic),(byte)9); byte[] residue=bulk(streamLogic).clone();
                // rt belongs to the prior write instance; use its matching owner.
                refuse(0x6700,()->stream(streamLogic,0x30,0,0,INPUT,0,3,out,7,190,bad.array,bad.offset,bad.capacity),"testWorkspaceBounds "+bad.name);
                require(Arrays.equals(residue,bulk(streamLogic)) && ((byte[])field(rt,"resetMarker"))[0]==0,"testInvalidScratchPreservesResetResidue");
            }
        }
        // Capacity zero at the exact end is valid; the consumer opts into no scratch.
        Logic l=new Logic();l.required=0;byte[] empty=new byte[0],out=filled(220);
        require(ordinary(l,4,null,0,0,out,7,190,empty,0,0)==2,"testZeroCapacityBoundary");
        byte[] end=filled(300);require(ordinary(l,5,INPUT,0,3,out,7,190,end,300,0)==0,"testZeroCapacityBoundary");
        l=new Logic();l.required=0;prepareUpload(l,end,300,0);byte[] close=closeData(INPUT);
        require(stream(l,0x21,0,0,close,0,34,out,7,190,end,300,0)==177,"testZeroCapacityBoundary");
        l=new Logic();l.required=0;require(stream(l,0x30,0,0,INPUT,0,3,out,7,190,empty,0,0)==35,"testZeroCapacityBoundary");
    }
    // Business minima, not renderer policy: 133 and just-below are refused before
    // effects, and exact 196/260 admit and recover on all six callback categories.
    static void testBusinessMinima() throws Exception {
        for(int minimum:new int[]{196,260})for(int kind=1;kind<=7;kind++)for(int capacity:new int[]{133,minimum-1,minimum}){
            Logic l=new Logic();l.required=(short)minimum;byte[] scratch=filled(300),out=filled(240),close=closeData(INPUT);final int method=kind;
            if(kind==6)prepareUpload(l,scratch,17,capacity);
            Action action=()->{if(method<=5)ordinary(l,method,method==5?INPUT:null,0,method==5?3:0,out,7,190,scratch,17,capacity);
                else stream(l,method==6?0x21:0x30,0,0,method==6?close:INPUT,0,method==6?34:3,out,7,190,scratch,17,capacity);};
            if(capacity<minimum){refuse(0x6A84,action,"testBusinessMinimum");require(l.calls==1 && l.effects==0,"testBusinessBeforeEffects");outside(scratch,0,0,"testBusinessBeforeEffects");outside(out,0,0,"testBusinessBeforeEffects");
                if(kind==6){l.calls=0;prepareUpload(l,scratch,17,minimum);}
                if(kind<=5)ordinary(l,kind,kind==5?INPUT:null,0,kind==5?3:0,out,7,190,scratch,17,minimum);
                else stream(l,kind==6?0x21:0x30,0,0,kind==6?close:INPUT,0,kind==6?34:3,out,7,190,scratch,17,minimum);
                require(l.effects==1,"testBusinessRetry");
            }else{action.run();require(l.calls==1 && l.effects==1,"testBusinessMinimum");}
            outside(scratch,17,minimum,"testScratchSentinels");noBorrowed(l,out,scratch,close);
        }
    }
    static void testOutputAndCountGuards() throws Exception {
        byte[] scratch=filled(300),out=filled(240),close=closeData(INPUT);
        Logic l=new Logic();final Logic shortOutput=l;
        refuse(0x6700,()->ordinary(shortOutput,1,null,0,0,out,7,126,scratch,17,260),"testReplyGuard");require(l.calls==0,"testReplyBeforeEffects");
        for(int length:new int[]{-1,126,128}){l=new Logic();l.forcedProduced=(short)length;final Logic wrong=l;refuse(0x6700,()->ordinary(wrong,1,null,0,0,out,7,190,scratch,17,260),"testProducedGuard");require(l.calls==1,"testProducedGuard");}
        for(int length:new int[]{-1,176,178}){l=new Logic();prepareUpload(l,scratch,17,260);l.forcedProduced=(short)length;final Logic wrong=l;refuse(0x6700,()->stream(wrong,0x21,0,0,close,0,34,out,7,190,scratch,17,260),"testStreamProducedGuard");require(l.calls==1,"testStreamProducedGuard");for(byte b:bulk(l))require(b==0,"testStreamCleanup");}
        for(int length:new int[]{-1,0,301}){l=new Logic();l.forcedProduced=(short)length;final Logic wrong=l;Arrays.fill(out,SENTINEL);refuse(0x6700,()->stream(wrong,0x30,0,0,INPUT,0,3,out,7,190,scratch,17,260),"testStreamProducedGuard");outside(out,0,0,"testNoPartialReply");}
        l=new Logic();prepareUpload(l,scratch,17,260);final Logic invalidReply=l;
        refuse(0x6700,()->stream(invalidReply,0x21,0,0,close,0,34,out,7,176,scratch,17,260),"testReplyGuard");require(l.calls==0,"testReplyBeforeEffects");
        for(byte b:bulk(l))require(b==0,"testStreamCleanup");
        l=new Logic();final Logic invalidInput=l;
        refuse(0x6700,()->ordinary(invalidInput,5,INPUT,1,3,out,7,190,scratch,17,260),"testRequestGuard");require(l.calls==0,"testRequestGuard");
        refuse(0x6700,()->ordinary(invalidInput,1,null,0,0,out,240,1,scratch,17,260),"testReplyGuard");require(l.calls==0,"testReplyGuard");
        require(ordinary(l,1,null,0,0,out,7,190,scratch,17,260)==127,"testGuardRetry");
    }
    public static void main(String[] args) throws Exception {
        new Simulator();
        group("testOrdinaryDisjoint", CallerWorkspaceHarness::testOrdinaryDisjoint);
        group("testOverlapLiveness", CallerWorkspaceHarness::testOverlapLiveness);
        group("testStreamPathsAndLifetime", CallerWorkspaceHarness::testStreamPathsAndLifetime);
        group("testWorkspaceBoundsAndRetry", CallerWorkspaceHarness::testWorkspaceBoundsAndRetry);
        group("testBusinessMinima", CallerWorkspaceHarness::testBusinessMinima);
        group("testOutputAndCountGuards", CallerWorkspaceHarness::testOutputAndCountGuards);
        System.out.println("caller workspace: six named behavioral groups passed; ordinary five shapes, CLOSE_WRITE, response-only");
    }
    interface CheckedAction { void run() throws Exception; }
    static void group(String name, CheckedAction action) throws Exception {
        try { action.run(); }
        catch (ISOException | WorkspaceDemoSkeleton.StatusWordException unexpected) {
            throw new AssertionError(name + " unexpected production refusal", unexpected);
        }
    }
}
