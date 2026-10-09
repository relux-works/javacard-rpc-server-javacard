package io.jcrpc.workspace;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;
import java.util.Arrays;
import java.security.MessageDigest;

/** Real APDU/send lane; simulator array size cannot attest physical SD access. */
public final class CallerWorkspaceAPDUHarness {
    static Simulator simulator;
    static void require(boolean b,String claim){if(!b)throw new AssertionError(claim);}
    static byte[] send(int ins,int p1,int p2,byte[] data){
        byte[] command=new byte[data.length==0?4:5+data.length];command[0]=(byte)0x80;command[1]=(byte)ins;command[2]=(byte)p1;command[3]=(byte)p2;
        if(data.length>0){command[4]=(byte)data.length;System.arraycopy(data,0,command,5,data.length);}
        return simulator.transmitCommand(command);
    }
    static void status(byte[] reply,int sw,String claim){require(reply.length>=2 && (reply[reply.length-2]&255)==(sw>>>8) && (reply[reply.length-1]&255)==(sw&255),claim);}
    static void exact(byte[] reply,int n,int value,String claim){status(reply,0x9000,claim);require(reply.length==n+2,claim);for(int i=0;i<n;i++)require(reply[i]==(byte)value,claim);}
    static void testOrdinaryAPDU(){
        for(int ins=1;ins<=3;ins++)exact(send(ins,0,0,new byte[0]),new int[]{0,127,190,177}[ins],ins,"testOrdinaryAPDU");
        require(Arrays.equals(send(4,0,0,new byte[0]),new byte[]{0x12,0x34,(byte)0x90,0}),"testScalarAPDU");
        require(Arrays.equals(send(5,0,0,new byte[]{11,22,33}),new byte[]{(byte)0x90,0}),"testVoidAPDU");
    }
    static void testRefusalsSendOnlySW(){
        for(int ins=1;ins<=5;ins++){
            byte[] input=ins==5?new byte[]{11,22,33}:new byte[0];
            require(Arrays.equals(send(ins,1,0,input),new byte[]{0x6A,(byte)0x84}),"test133BPhaseRefusal");
        }
        require(Arrays.equals(send(1,0,1,new byte[0]),new byte[]{0x67,0}),"testNoPartialAPDUSend");
        require(Arrays.equals(send(5,0,0,new byte[]{11,22}),new byte[]{0x67,0}),"testNoPartialAPDUSend");
        testOrdinaryAPDU();
    }
    static void testStreamAPDU()throws Exception{
        byte[] input={11,22,33};require(Arrays.equals(send(0x20,0,1,input),new byte[]{(byte)0x90,0}),"testStreamAPDU write");
        byte[] close=new byte[34];close[1]=3;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(input),0,close,2,32);
        exact(send(0x21,0,0,close),177,6,"testStreamAPDU close");exact(send(0x21,0,0,close),177,6,"testStreamAPDU replay");
        byte[] descriptor=send(0x30,0,0,input);status(descriptor,0x9000,"testStreamAPDU invoke");require(descriptor.length==37 && descriptor[0]==4 && descriptor[2]==127,"testStreamAPDU descriptor");
        byte[] result=new byte[127];int off=0;
        for(int i=0;i<4;i++){byte[] chunk=send(0x33,i,4,new byte[0]);status(chunk,0x9000,"testStreamAPDU read");System.arraycopy(chunk,0,result,off,chunk.length-2);off+=chunk.length-2;}
        require(off==127,"testStreamAPDU result");for(byte b:result)require(b==7,"testStreamAPDU result");
        close[1]=127;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(result),0,close,2,32);
        require(Arrays.equals(send(0x34,0,0,close),new byte[]{(byte)0x90,0}),"testStreamAPDU cleanup");
    }
    public static void main(String[] args)throws Exception{
        simulator=new Simulator();byte[] bytes={(byte)0xF0,0,0,1,4,1};AID aid=new AID(bytes,(short)0,(byte)bytes.length);
        simulator.installApplet(aid,CallerWorkspaceApplet.class);simulator.selectApplet(aid);
        testOrdinaryAPDU();testRefusalsSendOnlySW();testStreamAPDU();
        System.out.println("caller workspace actual simulator APDU/send/refusal/retry/stream paths passed");
    }
}
