package codegen

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"testing"

	"github.com/relux-works/javacard-rpc/pluginapi"
)

var cleanupModes = []string{pluginapi.StreamWorkspaceCleanupWholeReplyArea}

// Plugin.Generate rejects invalid selectors and storage combinations without a
// partial package; valid modes and the released empty selector remain reachable.
func TestPersistentCleanupSelectorRefusals(t *testing.T) {
	for _, mode := range append(append([]string{"", "unknown", "written-bytes-only", "Written-bytes-only"}, cleanupModes...), "whole-reply-area ") {
		for _, storage := range []string{"", "transient", "persistent"} {
			s := workspaceSchema(t, storage)
			s.Applet.StreamWorkspaceCleanup = mode
			files, err := (Plugin{}).Generate(s, pluginapi.Options{Namespace: "io.jcrpc.test", SimulatorDependency: "com.klinec:jcardsim:3.0.5.9"})
			valid := mode == "" || storage == "persistent" && mode == cleanupModes[0]
			if valid && (err != nil || len(files) == 0) {
				t.Fatalf("valid %s/%s: %v", storage, mode, err)
			}
			if !valid && (err == nil || files != nil) {
				t.Fatalf("invalid %s/%s admitted", storage, mode)
			}
		}
	}
}

func cleanupResult(t *testing.T, mode string, memory StreamMemory) *JavaGenerationResult {
	t.Helper()
	s := workspaceSchema(t, "persistent")
	s.Applet.StreamWorkspaceCleanup = mode
	r, e := GenerateJavaSkeletonWithOptions(s, "io.jcrpc.streamdemo.server", JavaOptions{StreamMemory: memory})
	if e != nil {
		t.Fatal(e)
	}
	return r
}

// Real Simulator.transmitCommand -> Applet.process -> processIfStream ->
// dispatchStreamTo covers cleanup, bounds, retries, reset and handler lifetime.
// Logical stores count byte assignments including same-valued zero stores;
// this establishes no physical timing, endurance or transaction atomicity.
func TestPersistentCleanupRealLifecycle(t *testing.T) {
	jar := simulatorJar(t)
	for _, mode := range cleanupModes {
		for _, memory := range []StreamMemory{StreamMemoryClearOnDeselect, StreamMemoryClearOnReset} {
			t.Run(mode+"/"+string(memory), func(t *testing.T) {
				r := cleanupResult(t, mode, memory)
				fixture := cleanupApplet()
				h := cleanupHarness
				t.Log(runRealJava(t, jar, instrumentCleanup(t, r), fixture, h, "CleanupHarness"))
			})
		}
	}
}

// Each plant retains its guard or wipe and weakens one concrete rejection or
// range. Only the named behavioral assertion counts as a kill.
func TestPersistentCleanupNarrowingMutants(t *testing.T) {
	jar := simulatorJar(t)
	for _, tc := range []struct{ name, mode, from, to, assertion string }{
		{"whole-reply-returned-length", cleanupModes[0], "markWritten((short) 0, outputCapacity);", "markWritten((short) 0, (short) (outputCapacity == 64 ? 4 : outputCapacity));", "scratch tail cleanup"},
		{"reset-nine", cleanupModes[0], "if (resetMarker[0] == 0) {\n                // Reset", "if (resetMarker[0] == 0 && workspace[0] != 9) {\n                // Reset", "reset range"},
		{"reset-abort-nine", cleanupModes[0], "if (resetMarker[0] == 0) {\n            wipe(workspace);", "if (resetMarker[0] == 0 && workspace[0] != 9) {\n            wipe(workspace);", "reset abort range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := cleanupResult(t, tc.mode, StreamMemoryClearOnDeselect)
			source := string(r.StreamRuntimeSource)
			if strings.Count(source, tc.from) != 1 {
				t.Fatalf("mutation anchor count %d", strings.Count(source, tc.from))
			}
			r.StreamRuntimeSource = []byte(strings.Replace(source, tc.from, tc.to, 1))
			h := cleanupHarness
			out, e := runRealJavaResult(t, jar, instrumentCleanup(t, r), cleanupApplet(), h, "CleanupHarness")
			if e == nil || !strings.Contains(out, "AssertionError: "+tc.assertion) {
				t.Fatalf("survivor (no named failure): %v\n%s", e, out)
			}
			t.Logf("killed %s by TestPersistentCleanupRealLifecycle: %s", tc.name, tc.assertion)
		})
	}
}

func instrumentCleanup(t *testing.T, r *JavaGenerationResult) *JavaGenerationResult {
	t.Helper()
	result := *r
	src := string(r.StreamRuntimeSource)
	for _, p := range [][2]string{
		{"            workspace[i] = (byte) 0;", "            CleanupHarness.cleanup++;\n            workspace[i] = (byte) 0;"},
		{"            value[i] = (byte) 0;", "            if(value == workspace) CleanupHarness.cleanup++;\n            value[i] = (byte) 0;"},
		{"            target[(short) (targetOffset + i)] = source[(short) (sourceOffset + i)];", "            if(target == workspace) CleanupHarness.stores++;\n            target[(short) (targetOffset + i)] = source[(short) (sourceOffset + i)];"},
	} {
		src = strings.ReplaceAll(src, p[0], p[1])
	}
	result.StreamRuntimeSource = []byte(src)
	return &result
}

func cleanupApplet() string {
	signature := "byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset, short outputCapacity"
	packet := `short n=inputLength; for(short l=0,r=(short)(n-1);l<=r;l++,r--){byte v=input[l];output[l]=input[r];CleanupHarness.stores++;output[r]=v;CleanupHarness.stores++;} return n;`
	report := `short n=(short)(control==2||control==3?64:4);
 if(control==4)failStream((short)0x6985);
 for(short i=0;i<n;i++){output[i]=(byte)(control==3?0:9);CleanupHarness.stores++;}
 if(control==3)failStream((short)0x6985);return (short)4;`
	return strings.NewReplacer("SIGNATURE", signature, "PACKET", packet, "REPORT", report).Replace(cleanupAppletTemplate)
}

const cleanupAppletTemplate = `package io.jcrpc.streamdemo.server;
import javacard.framework.*;
public final class StreamDemoApplet extends Applet {
 static StreamDemoApplet installed;final Logic logic=new Logic();final StreamDemoStreamAPDUAdapter adapter=new StreamDemoStreamAPDUAdapter(logic);
 public static void install(byte[] b,short o,byte l){new StreamDemoApplet().register();}
 StreamDemoApplet(){installed=this;}
 public void process(APDU a){if(selectingApplet())return;adapter.processIfStream(a);}
 public void deselect(){adapter.deselect();}
 static int control=1;
 static final class Logic extends StreamDemoSkeleton {
  Logic(){super(null);}protected byte onGetVersion(){return 1;}
  protected short onProcessPacketStream(SIGNATURE){PACKET}
  protected short onIssueReportStream(SIGNATURE){REPORT}
 }
}
`
const cleanupHarness = `package io.jcrpc.streamdemo.server;
import javacard.framework.*;
import com.licel.jcardsim.base.*;
import java.lang.reflect.*;
import java.util.*;
import java.security.MessageDigest;
public class CleanupHarness {
 static Simulator simulator;static AID aid,other;static StreamDemoApplet applet;static byte[] workspace;static Object session;
 static int stores,cleanup;
 public static void main(String[] args)throws Exception{
  simulator=new Simulator();aid=new AID(new byte[]{(byte)0xF0,0,0,1,2,1},(short)0,(byte)6);other=new AID(new byte[]{(byte)0xF0,0,0,1,2,2},(short)0,(byte)6);
  simulator.installApplet(aid,StreamDemoApplet.class);simulator.installApplet(other,EmptyApplet.class);simulator.selectApplet(aid);applet=StreamDemoApplet.installed;
  session=field(applet.logic,"streamSession");workspace=(byte[])field(session,"workspace");
  resetCounts();deselect();if(stores!=0||cleanup!=0)throw new AssertionError("untouched session");
  byte[] head=new byte[192];Arrays.fill(head,(byte)9);
  for(int end=0;end<3;end++){
   resetCounts();send(0x20,0,2,head);if(stores!=192)throw new AssertionError("request write count");send(0x20,0,2,head);if(stores!=192)throw new AssertionError("retry wrote twice");
   if(end==0)send(0x25,0,0,new byte[0]);if(end==1)deselect();if(end==2){byte[] bad=head.clone();bad[1]=8;reject(0x6A80,0x20,0,2,bad);}
   if(cleanup!=192)throw new AssertionError("request cleanup range");zero();int before=cleanup;deselect();if(before!=cleanup)throw new AssertionError("double deselect cleanup");reject(0x6985,0x22,0,0,new byte[0]);
  }
  for(int control:new int[]{1,2}){
   StreamDemoApplet.control=control;resetCounts();byte[] descriptor=send(0x30,0,0,new byte[0]);
   if(descriptor.length!=35 || descriptor[2]!=4)throw new AssertionError("response control");
   send(0x34,0,0,Arrays.copyOfRange(descriptor,1,35));
   if(cleanup!=64)throw new AssertionError("scratch tail cleanup");zero();
   int before=cleanup;send(0x34,0,0,Arrays.copyOfRange(descriptor,1,35));if(before!=cleanup)throw new AssertionError("READ close double wipe");
   deselect();if(before!=cleanup)throw new AssertionError("closed deselect writes");
  }
  for(int control:new int[]{3,4}){
   StreamDemoApplet.control=control;resetCounts();reject(0x6985,0x30,0,0,new byte[0]);
   if(cleanup!=64)throw new AssertionError("zero failure range");zero();
  }
  StreamDemoApplet.control=1;
  resetCounts();send(0x20,0,2,head);simulator.reset();simulator.selectApplet(aid);reject(0x6985,0x22,0,0,new byte[0]);
  if(cleanup!=workspace.length)throw new AssertionError("reset range");zero();
  byte[] valid={1,2,3};send(0x20,0,1,valid);byte[] descriptor=send(0x21,0,0,close(valid));
  if(!Arrays.equals(new byte[]{3,2,1},send(0x23,0,1,new byte[0])))throw new AssertionError("fresh wire control");send(0x24,0,0,Arrays.copyOfRange(descriptor,1,35));zero();
  send(0x20,0,2,head);simulator.reset();simulator.selectApplet(aid);resetCounts();deselect();
  if(cleanup!=workspace.length)throw new AssertionError("reset abort range");zero();
  System.out.println("lifecycle/bounds/lifetime/reset controls green");
 }
 static void resetCounts(){stores=cleanup=0;}
 static void deselect(){simulator.selectApplet(other);simulator.selectApplet(aid);}
 static void zero(){for(byte b:workspace)if(b!=0)throw new AssertionError("workspace residue");}
 static byte[] send(int ins,int p1,int p2,byte[] data){byte[] a=new byte[data.length==0?4:data.length+5];a[0]=(byte)0xB0;a[1]=(byte)ins;a[2]=(byte)p1;a[3]=(byte)p2;if(data.length>0){a[4]=(byte)data.length;System.arraycopy(data,0,a,5,data.length);}byte[] r=simulator.transmitCommand(a);int n=r.length;short sw=(short)(((r[n-2]&255)<<8)|(r[n-1]&255));if(sw!=(short)0x9000)ISOException.throwIt(sw);return Arrays.copyOf(r,n-2);}
 static void reject(int sw,int ins,int p1,int p2,byte[] data){try{send(ins,p1,p2,data);throw new AssertionError("expected refusal "+sw);}catch(ISOException e){if((e.getReason()&65535)!=sw)throw new AssertionError("wrong refusal "+Integer.toHexString(e.getReason()&65535));}}
 static byte[] close(byte[] data)throws Exception{byte[] r=new byte[34];r[0]=(byte)(data.length>>8);r[1]=(byte)data.length;System.arraycopy(MessageDigest.getInstance("SHA-256").digest(data),0,r,2,32);return r;}
 static Object field(Object x,String n)throws Exception{Class<?> c=x.getClass();while(c!=null){try{Field f=c.getDeclaredField(n);f.setAccessible(true);return f.get(x);}catch(NoSuchFieldException e){c=c.getSuperclass();}}throw new NoSuchFieldException(n);}
 public static class EmptyApplet extends Applet{public static void install(byte[] b,short o,byte l){new EmptyApplet().register();}public void process(APDU a){}}
}
`

// The keeper measured these five real Auth production files. Matching their
// immutable hashes binds the narrowed whole-only generator to that execution;
// it does not claim to replay the consumer, provider internals or reset metrics.
func TestPersistentCleanupWholeMeasuredAuthIdentity(t *testing.T) {
	s, err := ParseFile("testdata/bsim-auth.json")
	if err != nil {
		t.Fatal(err)
	}
	// The frozen allocation fixture has B6; the immutable real Auth IDL uses B4.
	s.Applet.CLA = 0xB4
	s.Applet.StreamWorkspace = "persistent"
	s.Applet.StreamWorkspaceCleanup = pluginapi.StreamWorkspaceCleanupWholeReplyArea
	files, err := (Plugin{}).Generate(s, pluginapi.Options{Namespace: "ru.mts.bsimid.applet.auth", StreamMemory: "clear_on_reset", SimulatorDependency: "works.relux:jcardsim:3.0.5.9-relux.2"})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"BSimAuthBoundedStreamRuntime.java": "5063f440b42c08619274cd16206541c55c98004acd3e3c8b727c26e9af9fb90f",
		"BSimAuthSkeleton.java":             "95950ee333dab0ba36d53066e77aa488ef0e15170184f0adbcbc3a5fbf15a724",
		"BSimAuthStreamAPDUAdapter.java":    "ffeabcbc5fd61f86ce2fbe66912f0d8d228a1fbde4ac10737934e5c9ce49c8f8",
		"BSimAuthStreamEndpoint.java":       "52af535eb9bf709701333862ea07d3e58f61f21ddbeac02da83465d525c05c09",
		"BSimAuthTransport.java":            "75ff6fd4b035769347be3c6debe4e458e0141a0544f2f779a727939c626fb279",
	}
	checked := 0
	for _, file := range files {
		want, ok := expected[path.Base(file.Name)]
		if !ok {
			continue
		}
		sum := sha256.Sum256(file.Data)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("measured Auth source drift: %s", file.Name)
		}
		checked++
	}
	if checked != len(expected) {
		t.Fatalf("measured source coverage %d of %d", checked, len(expected))
	}
}
