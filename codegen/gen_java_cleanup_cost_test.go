package codegen

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Actual jCardSim runs the generated example in four workloads, with an
// instrumented logical-store/call observer. Sizes are example-specific: 1792 B
// provisioning, 320 B issuance, 896 B abandoned partial request. The real Auth
// fixture is a separate lane; these handlers are never labeled as Auth.
func TestPersistentCleanupExampleComparison(t *testing.T) {
	jar := simulatorJar(t)
	for _, mode := range append([]string{""}, cleanupModes...) {
		t.Run(mode, func(t *testing.T) {
			output, err := runExampleCost(t, jar, mode, false)
			if err != nil {
				t.Fatalf("real example comparison: %v\n%s", err, output)
			}
			t.Log(output)
		})
	}
}

func runExampleCost(t *testing.T, jar, mode string, plant bool) (string, error) {
	r := cleanupResult(t, mode, StreamMemoryClearOnDeselect)
	size := len(r.TransportSource) + len(r.SkeletonSource) + len(r.StreamEndpointSource) + len(r.StreamRuntimeSource) + len(r.StreamAPDUAdapterSource)
	fixture := streamDemoAppletFixture
	fixture = strings.Replace(fixture, "private final Logic logic;", "static StreamDemoApplet installed;\n    private final byte[] noData=new byte[0];\n    private final Logic logic;", 1)
	fixture = strings.Replace(fixture, "StreamDemoApplet() {", "StreamDemoApplet() {\n        installed=this;", 1)
	fixture = strings.Replace(fixture, "ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);", "byte[] response=apdu.getBuffer(); short produced=logic.dispatchTo((byte)1,(byte)0,(byte)0,null,(short)0,(short)0,response,(short)5,(short)(response.length-5), response, (short)5, (short)(response.length-5)); apdu.setOutgoing(); apdu.setOutgoingLength(produced); apdu.sendBytesLong(response,(short)5,produced);", 1)
	// Observe actual scalar handler stores separately from runtime request/copy
	// and cleanup stores.
	fixture = strings.ReplaceAll(fixture, "output[(short) (outputOffset + left)] =", "ExampleCostHarness.stores++;output[(short) (outputOffset + left)] =")
	fixture = strings.ReplaceAll(fixture, "output[(short) (outputOffset + right)] =", "ExampleCostHarness.stores++;output[(short) (outputOffset + right)] =")
	instrumented := instrumentCleanup(t, r)
	src := strings.ReplaceAll(string(instrumented.StreamRuntimeSource), "CleanupHarness", "ExampleCostHarness")
	src = strings.Replace(src, "if (resetMarker[0] == 0) {", "if (resetMarker[0] == 0) {\n                ExampleCostHarness.resetBytes += workspace.length;", 1)
	instrumented.StreamRuntimeSource = []byte(src)
	entries := regexp.MustCompile(`(?m)^\s+(?:private|public|protected)(?: final| static)? (?:short|void|boolean|int|byte|byte\[\]) \w+\([^{};]*\) \{`)
	observeCalls := func(source string) string {
		return entries.ReplaceAllStringFunc(source, func(s string) string { return s + "\n        ExampleCostHarness.calls++;" })
	}
	for _, source := range []*[]byte{&instrumented.TransportSource, &instrumented.SkeletonSource, &instrumented.StreamRuntimeSource, &instrumented.StreamAPDUAdapterSource, &instrumented.StreamEndpointSource} {
		*source = []byte(observeCalls(string(*source)))
	}
	fixture = observeCalls(fixture)
	if plant {
		anchor := "if(target == workspace) ExampleCostHarness.stores++;"
		if strings.Count(string(instrumented.StreamRuntimeSource), anchor) != 1 {
			t.Fatal("counter plant anchor")
		}
		instrumented.StreamRuntimeSource = []byte(strings.Replace(string(instrumented.StreamRuntimeSource), anchor, "if(target == workspace && targetOffset != 768) ExampleCostHarness.stores++;", 1))
	}
	h := strings.NewReplacer("MODE", mode, "SOURCE_BYTES", fmt.Sprint(size), "TRACKED", fmt.Sprint(mode != "")).Replace(exampleCostHarness)
	return runRealJavaResult(t, jar, instrumented, fixture, h, "ExampleCostHarness")
}

// The observer must reject omission of precisely the fifth request chunk's
// stores. All product writes still run; unrelated Java failures are not a kill.
func TestPersistentCleanupExampleCounterPlant(t *testing.T) {
	jar := simulatorJar(t)
	output, err := runExampleCost(t, jar, cleanupModes[0], true)
	if err == nil || !strings.Contains(output, "AssertionError: logical write counter control") {
		t.Fatalf("counter survivor: %v\n%s", err, output)
	}
	t.Log("killed fifth-request-chunk-count-omission by TestPersistentCleanupExampleComparison/logical write counter control")
}

const exampleCostHarness = `package io.jcrpc.streamdemo.server;
import javacard.framework.*;
import com.licel.jcardsim.base.*;
import java.util.*;
import java.lang.reflect.*;
import java.security.MessageDigest;
public class ExampleCostHarness {
 static Simulator simulator;static AID aid,other;static StreamDemoApplet applet;static byte[] workspace;
 static int stores,cleanup,calls,commands,minCalls,maxCalls,resetBytes;
 static Set<Object> seen;static int ram,nvm,refs,arrays;
 public static void main(String[] args)throws Exception{
  System.out.println("mode=MODE; generated Java=SOURCE_BYTES B");
  for(String workload:new String[]{"untouched","provisioning","issuance","mid-stream failure"}){
   simulator=new Simulator();aid=new AID(new byte[]{(byte)0xF0,0,0,1,2,1},(short)0,(byte)6);other=new AID(new byte[]{(byte)0xF0,0,0,1,2,2},(short)0,(byte)6);
   simulator.installApplet(aid,StreamDemoApplet.class);simulator.installApplet(other,EmptyApplet.class);simulator.selectApplet(aid);applet=StreamDemoApplet.installed;
   workspace=(byte[])field(field(field(applet,"logic"),"streamSession"),"workspace");
   inventory();int startRAM=ram,startArrays=arrays;
   stores=cleanup=calls=commands=maxCalls=resetBytes=0;minCalls=Integer.MAX_VALUE;
   if(workload.equals("untouched")){if(!Arrays.equals(new byte[]{1},send(1,0,0,new byte[0])))throw new AssertionError("untouched version positive control");}
   else {
    int size=workload.equals("provisioning")?1792:workload.equals("issuance")?320:896;
    byte[] request=new byte[size];for(int i=0;i<size;i++)request[i]=(byte)(i+1);
    int count=(size+191)/192;
    for(int i=0;i<count;i++)send(0x20,i,count,Arrays.copyOfRange(request,i*192,Math.min(size,(i+1)*192)));
    if(workload.equals("mid-stream failure")){
     // An explicit host-failure abort while half the declared capacity is
     // buffered: no handler executes and no fake successful result is counted.
     send(0x25,0,0,new byte[0]);
    } else {
     byte[] descriptor=send(0x21,0,0,close(request));
     byte[] result=new byte[size];int resultCount=descriptor[0]&255;
     for(int i=0;i<resultCount;i++){byte[] chunk=send(0x23,i,resultCount,new byte[0]);System.arraycopy(chunk,0,result,i*192,chunk.length);}
     for(int i=0;i<size;i++)if(result[i]!=request[size-1-i])throw new AssertionError("comparison wire");
     send(0x24,0,0,Arrays.copyOfRange(descriptor,1,35));
    }
    int outputStores=workload.equals("mid-stream failure")?0:size;
    if(stores!=size+outputStores)throw new AssertionError("logical write counter control");
    int erased=(!workload.equals("mid-stream failure"))?1792:size;
    if(TRACKED && cleanup!=erased)throw new AssertionError("comparison cleanup range");
   }
   int before=cleanup;simulator.selectApplet(other);simulator.selectApplet(aid);int deselect=cleanup-before;
   if(TRACKED && deselect!=0)throw new AssertionError("comparison deselect repeats cleanup");
   if(workload.equals("untouched") && (stores!=0||cleanup!=(TRACKED?0:1792)))throw new AssertionError("comparison untouched");
   for(byte b:workspace)if(b!=0)throw new AssertionError("comparison residue");
   inventory();if(ram!=startRAM || arrays!=startArrays)throw new AssertionError("command array allocation");
   System.out.println(workload+" | workspace stores="+stores+" | cleanup="+cleanup+" | reset="+resetBytes+" | total="+(stores+cleanup)+" | deselect="+deselect+" | transient primitive="+ram+" | generated NVM array payload="+nvm+" | transient reference slots="+refs+" | arrays="+arrays+" | commands="+commands+" | owned methods/command="+minCalls+".."+maxCalls);
  }
 }
 static void inventory()throws Exception{seen=Collections.newSetFromMap(new IdentityHashMap<Object,Boolean>());ram=nvm=refs=arrays=0;walk(field(applet,"logic"));walk(field(applet,"streams"));}
 static void walk(Object x)throws Exception{if(x==null||!seen.add(x))return;Class<?> c=x.getClass();if(c.isArray()){int n=Array.getLength(x);Class<?> k=c.getComponentType();int b=k==byte.class?n:k==short.class?2*n:0;boolean tr=JCSystem.isTransient(x)!=JCSystem.NOT_A_TRANSIENT_OBJECT;if(tr){ram+=b;if(!k.isPrimitive())refs+=n;}else nvm+=b;arrays++;return;}while(c!=null&&c.getName().startsWith("io.jcrpc.streamdemo.server.")){for(Field f:c.getDeclaredFields()){if(!f.getType().isPrimitive()){f.setAccessible(true);walk(f.get(Modifier.isStatic(f.getModifiers())?null:x));}}c=c.getSuperclass();}}
 static short arrayCopy(byte[] s,short so,byte[] d,short o,short n){short result=Util.arrayCopy(s,so,d,o,n);if(d==workspace)stores+=n;return result;}
 static byte[] send(int ins,int p1,int p2,byte[] data){int before=calls;byte[] a=new byte[data.length==0?4:data.length+5];a[0]=(byte)0xB0;a[1]=(byte)ins;a[2]=(byte)p1;a[3]=(byte)p2;if(data.length>0){a[4]=(byte)data.length;System.arraycopy(data,0,a,5,data.length);}byte[] r=simulator.transmitCommand(a);int n=r.length;short sw=(short)(((r[n-2]&255)<<8)|(r[n-1]&255));if(sw!=(short)0x9000)throw new AssertionError("comparison status "+Integer.toHexString(sw&65535));int used=calls-before;commands++;minCalls=Math.min(minCalls,used);maxCalls=Math.max(maxCalls,used);return Arrays.copyOf(r,n-2);}
 static byte[] close(byte[] data)throws Exception{byte[] r=new byte[34];r[0]=(byte)(data.length>>8);r[1]=(byte)data.length;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(data),0,r,2,32);return r;}
 static Object field(Object x,String n)throws Exception{Class<?> c=x.getClass();while(c!=null){try{Field f=c.getDeclaredField(n);f.setAccessible(true);return f.get(x);}catch(NoSuchFieldException e){c=c.getSuperclass();}}throw new NoSuchFieldException(n);}
 public static class EmptyApplet extends Applet{public static void install(byte[] b,short o,byte l){new EmptyApplet().register();}public void process(APDU a){}}
}
`
