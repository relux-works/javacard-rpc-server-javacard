package io.jcrpc.writer;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;

/** JVM fixtures drive the generated dispatchTo entry. The fake caller sends
 * only after a successful return; no physical APDU behavior is claimed.
 * Subclasses are trusted to respect windows and never retain APDU references.
 */
public final class OrdinaryOutputSpanHarness {
    static final short WRONG_LENGTH = (short)0x6700;
    static final byte SENTINEL = (byte)0xA5;
    static String witness;
    static int sends;
    static byte[] sent;

    public static void main(String[] args) throws Exception {
        testFixedWire();
        testInsufficientCapacity();
        testProducedLength();
        testVariableProducedLength();
        testInvalidWindows();
        testRequestAndRouting();
        testOverlap();
        testScalarAndVoid();
        testNoRetainedReferences();
    }

    static void require(boolean condition) {
        if (!condition) throw new AssertionError(witness);
    }

    // Sent bytes are exactly the declared width at the requested nonzero offset.
    static void testFixedWire() {
        witness = "testFixedWire";
        Logic l = new Logic();
        for (int ins = 1; ins <= 4; ins++) {
            int width = widths[ins-1];
            byte[] buffer = new byte[ins <= 2 ? 133 : 200];
            Arrays.fill(buffer, SENTINEL);
            int offset = ins == 1 ? 6 : 7;
            call(l, ins, null, 0, 0, buffer, offset, buffer.length-offset);
            require(sent.length == width && l.lastCapacity == width);
            for (int i=0; i<width; i++) require(sent[i] == (byte)(i+ins));
            for (int i=0; i<offset; i++) require(buffer[i] == SENTINEL);
            for (int i=offset+width; i<buffer.length; i++) require(buffer[i] == SENTINEL);
        }
    }
    static final int[] widths = {127,13,190,177};

    // Insufficient capacity refuses before the handler or transmission; issuer
    // replies are whole-only and require a caller/transport with enough space.
    static void testInsufficientCapacity() {
        witness = "testInsufficientCapacity";
        Logic l=new Logic(); byte[] buffer=new byte[200]; Arrays.fill(buffer,SENTINEL);
        for(int ins=1; ins<=4; ins++) {
            reject(l,ins,null,0,0,buffer,0,widths[ins-1]-1,WRONG_LENGTH);
            require(l.calls==0);
            for(byte b:buffer) require(b==SENTINEL);
        }
        for(int ins=3; ins<=4; ins++) {
            reject(l,ins,null,0,0,new byte[133],0,133,WRONG_LENGTH);
            require(l.calls==0);
        }
        call(l,1,null,0,0,buffer,0,127); require(sent.length==127);
    }

    // Wrong fixed produced lengths refuse; writes within the buffer can remain.
    // This does not sandbox a malicious handler writing outside its span.
    static void testProducedLength() {
        witness="testProducedLength"; Logic l=new Logic(); byte[] buffer=new byte[200];
        for(int ins=1;ins<=4;ins++) {
            for(int n:new int[]{-1,widths[ins-1]-1,widths[ins-1]+1,201}) {
                l.forced=n;reject(l,ins,null,0,0,buffer,0,200,WRONG_LENGTH);
            }
        }
        l.forced=Integer.MIN_VALUE;call(l,1,null,0,0,buffer,0,127); require(sent.length==127);
    }

    // Variable replies may be empty or fill capacity, but cannot be negative or
    // exceed it. These are bounds on the returned length, not on handler stores.
    static void testVariableProducedLength() {
        witness="testVariableProducedLength";Logic l=new Logic();byte[] buffer=new byte[20];byte[] request={0,0};
        for(int n:new int[]{-1,5}) {l.forced=n;reject(l,10,request,0,2,buffer,3,4,WRONG_LENGTH);}
        for(int n:new int[]{0,4}) {l.forced=n;call(l,10,request,0,2,buffer,3,4);require(sent.length==n);}
    }

    // Invalid windows refuse through dispatchTo before callback/send, including
    // short-end overflow values; helper int-overflow guards have valid controls.
    static void testInvalidWindows() {
        witness="testInvalidWindows"; Logic l=new Logic();byte[] b=new byte[133];
        int[][] windows={{-1,1},{0,-1},{134,0},{132,2},{32767,1},{1,32767},{32767,32767}};
        reject(l,9,null,0,0,null,0,0,WRONG_LENGTH);
        for(int[] w:windows) {
            reject(l,9,null,0,0,b,w[0],w[1],WRONG_LENGTH);
            reject(l,9,b,w[0],w[1],b,0,0,WRONG_LENGTH);
        }
        reject(l,9,null,1,0,b,0,0,WRONG_LENGTH);
        reject(l,9,null,0,1,b,0,0,WRONG_LENGTH);
        require(l.calls==0);
        call(l,9,b,133,0,b,133,0); require(sent.length==0 && l.calls==1);
        call(l,9,null,0,0,b,0,0); require(l.calls==2);
        require(l.helperRejects(b,Integer.MAX_VALUE,2));
        require(l.helperRejects(b,0,Integer.MAX_VALUE));
        require(l.helperRejects(b,132,2));
        require(l.helperCopy(b,0,b,0,1)==1);
        require(l.helperScalarRejects(b,Integer.MAX_VALUE,2));
        require(l.helperScalarRejects(b,Integer.MAX_VALUE,4));
        require(l.helperScalarRejects(b,132,2));
        require(l.helperScalarRejects(b,130,4));
        l.helperScalar(b,131,2);require(b[131]==0x12 && b[132]==0x34);
        l.helperScalar(b,129,4);require(b[129]==1 && b[132]==4);
    }

    // Unknown INS and both short/long fixed requests refuse without callback;
    // valid controls prove no-data, minimum variable prefix and typed routing.
    static void testRequestAndRouting() {
        witness="testRequestAndRouting"; Logic l=new Logic();byte[] b=new byte[133];
        reject(l,127,null,0,0,b,0,0,(short)0x6D00);
        for(int n:new int[]{5,7})reject(l,11,b,5,n,b,0,4,WRONG_LENGTH);
        reject(l,10,b,0,1,b,0,20,WRONG_LENGTH);
        reject(l,9,b,0,1,b,0,0,WRONG_LENGTH);
        require(l.calls==0);
        byte[] typed={0x12,0x34,0x01,0x02,0x03,0x04};
        call(l,11,typed,0,6,b,3,4);
        require(Arrays.equals(sent,new byte[]{0x01,0x02,0x11,0x30}));
        call(l,10,new byte[]{0,0},0,2,b,0,0); require(sent.length==0);
    }

    // All typed inputs are read before writes even at identical request/output
    // offsets. Borrowed bytes are copied using memmove in both overlap directions.
    static void testOverlap() {
        witness="testOverlap"; Logic l=new Logic();byte[] b=new byte[133];
        b[5]=0x12;b[6]=0x34;b[7]=1;b[8]=2;b[9]=3;b[10]=4;
        call(l,11,b,5,6,b,5,4);require(Arrays.equals(sent,new byte[]{1,2,0x11,0x30}));
        for(int destination:new int[]{0,5,6,7,8,9}) {
            Arrays.fill(b,SENTINEL);b[5]=0;b[6]=3;b[7]=11;b[8]=22;b[9]=33;
            call(l,10,b,5,5,b,destination,3);
            require(Arrays.equals(sent,new byte[]{11,22,33}));
        }
    }

    // Scalar big-endian/bool wire and void length remain unchanged.
    static void testScalarAndVoid() {
        witness="testScalarAndVoid";Logic l=new Logic();byte[] b=new byte[133];
        byte[][] expected={{(byte)0xFE},{1},{0x12,0x34},{1,2,3,4},{}};
        for(int ins=5;ins<=9;ins++){call(l,ins,null,0,0,b,5,128);require(Arrays.equals(sent,expected[ins-5]));}
        for(int ins=5;ins<=8;ins++) {
            int initial=l.calls;
            reject(l,ins,null,0,0,b,5,expected[ins-5].length-1,WRONG_LENGTH);
            require(l.calls==initial);
        }
    }

    // Snapshot generated instance/static reference fields, then reject command buffers retained
    // as a field/array element after success or refusal. This checks the generated
    // class and this compliant handler; it cannot constrain arbitrary subclasses.
    static void testNoRetainedReferences() throws Exception {
        witness="testNoRetainedReferences";Logic l=new Logic();byte[] b=new byte[133],request=new byte[133];
        Field[] fields=WriterDemoSkeleton.class.getDeclaredFields();Object[] before=new Object[fields.length];
        for(int i=0;i<fields.length;i++){fields[i].setAccessible(true);if(!fields[i].getType().isPrimitive())before[i]=fields[i].get(Modifier.isStatic(fields[i].getModifiers())?null:l);}
        call(l,1,request,5,0,b,6,127);reject(l,127,request,0,0,b,0,0,(short)0x6D00);
        for(int i=0;i<fields.length;i++)if(!fields[i].getType().isPrimitive()){
            Object value=fields[i].get(Modifier.isStatic(fields[i].getModifiers())?null:l);require(value==before[i] && value!=b && value!=request);
            if(value instanceof Object[])for(Object element:(Object[])value)require(element!=b && element!=request);
        }
    }

    // Fake adapter owns sending; failed dispatch never reaches this send site.
    static void call(Logic l,int ins,byte[] req,int off,int len,byte[] out,int outOff,int cap) {
        short produced=l.dispatchTo((byte)ins,(byte)0,(byte)0,req,(short)off,(short)len,out,(short)outOff,(short)cap);
        require(produced >= 0 && produced <= cap);
        sent=Arrays.copyOfRange(out,outOff,outOff+produced);sends++;
    }
    static void reject(Logic l,int ins,byte[] req,int off,int len,byte[] out,int outOff,int cap,short sw){
        int initial=sends;
        try{call(l,ins,req,off,len,out,outOff,cap);throw new AssertionError(witness);}
        catch(WriterDemoSkeleton.StatusWordException e){require(e.getStatusWord()==sw && sends==initial);}
    }
    static final class Logic extends WriterDemoSkeleton {
        int forced=Integer.MIN_VALUE,calls,lastCapacity;
        Logic(){super(null);}
        short fill(byte[] out,short off,short cap,int ins){
            calls++;lastCapacity=cap;
            for(short i=0;i<cap;i++)out[(short)(off+i)]=(byte)(i+ins);
            return forced==Integer.MIN_VALUE?cap:(short)forced;
        }
        protected short onGetAuthenticationIdentity(byte[] out,short off,short cap){return fill(out,off,cap,1);}
        protected short onGetAuthAppletInfo(byte[] out,short off,short cap){return fill(out,off,cap,2);}
        protected short onGetIssuer190(byte[] out,short off,short cap){return fill(out,off,cap,3);}
        protected short onGetIssuer177(byte[] out,short off,short cap){return fill(out,off,cap,4);}
        protected byte onScalar0(){calls++;return (byte)0xFE;}
        protected boolean onScalar1(){calls++;return true;}
        protected short onScalar2(){calls++;return (short)0x1234;}
        protected int onScalar3(){calls++;return 0x01020304;}
        protected void onClear(){calls++;}
        protected int onTyped(short first,int second){calls++;return second ^ (first & 0xFFFF);}
        protected short onEcho(short prefix,byte[] payload,short payloadOffset,short payloadLength,byte[] out,short off,short cap){
            calls++;require(prefix==payloadLength);
            if(forced!=Integer.MIN_VALUE)return (short)forced;
            if(payloadLength>cap)throw statusWordFailure(WRONG_LENGTH);
            packBytes(out,off,payload,payloadOffset,payloadLength);
            return payloadLength;
        }
        boolean helperRejects(byte[] b,int off,int len){
            try{packBytes(b,off,b,0,len);return false;}
            catch(StatusWordException e){return e.getStatusWord()==WRONG_LENGTH;}
            catch(RuntimeException e){return false;}
        }
        int helperCopy(byte[] out,int off,byte[] src,int srcOff,int length){return packBytes(out,off,src,srcOff,length);}
        void helperScalar(byte[] b,int off,int width){if(width==2)packU16(b,off,(short)0x1234);else packU32(b,off,0x01020304);}
        boolean helperScalarRejects(byte[] b,int off,int width){
            try{helperScalar(b,off,width);return false;}
            catch(StatusWordException e){return e.getStatusWord()==WRONG_LENGTH;}
            catch(RuntimeException e){return false;}
        }
    }
}
