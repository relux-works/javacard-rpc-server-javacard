package codegen

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The unchanged root runtime is exercised through Simulator.transmitCommand ->
// AppletBase.process: valid dispatch and response, wrong CLA without dispatch,
// unknown INS without a handler effect, and recovery. A separate unopened-channel
// refusal never reaches AppletBase. This does not open a physical card.
func TestRootAppletBaseRealSimulator(t *testing.T) {
	jar := simulatorJar(t)
	root := t.TempDir()
	harness := filepath.Join(root, "RootRuntimeHarness.java")
	writeTestFile(t, harness, []byte(rootRuntimeHarness))
	source := filepath.Join("..", "src", "main", "java", "io", "jcrpc", "server", "AppletBase.java")
	b, e := exec.Command("javac", "-cp", jar, "-d", root, source, harness).CombinedOutput()
	if e != nil {
		t.Fatalf("runtime javac: %v\n%s", e, b)
	}
	b, e = exec.Command("java", "-cp", root+string(filepath.ListSeparator)+jar, "RootRuntimeHarness").CombinedOutput()
	if e != nil {
		t.Fatalf("runtime simulator: %v\n%s", e, b)
	}
	if !strings.Contains(string(b), "root runtime controls passed") {
		t.Fatalf("missing controls: %s", b)
	}
}

const rootRuntimeHarness = `import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;
import io.jcrpc.server.AppletBase;
public final class RootRuntimeHarness {
 public static final class Probe extends AppletBase {
  static int calls,commands;
  public Probe(){super((byte)0xB0);}
  public static void install(byte[] b,short o,byte l){new Probe().register();}
  public void process(APDU a){if(!selectingApplet())commands++;super.process(a);}
  protected void dispatch(APDU a,byte ins){
   if(ins!=(byte)1)ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
   calls++;sendU16(a,(short)0x1234);
  }
 }
 static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format("%02X",b&255));return s.toString();}
 static void check(byte[] got,int...want){if(got.length!=want.length)throw new AssertionError("response length: got "+hex(got));for(int i=0;i<want.length;i++)if((got[i]&255)!=want[i])throw new AssertionError("response byte "+i+": got "+hex(got)+" expected "+java.util.Arrays.toString(want));}
 public static void main(String[]args){
  Simulator s=new Simulator();AID aid=new AID(new byte[]{(byte)0xF0,0,0,1,2,1},(short)0,(byte)6);
  s.installApplet(aid,Probe.class);s.selectApplet(aid);
  check(s.transmitCommand(new byte[]{(byte)0xB0,1,0,0}),0x12,0x34,0x90,0);
  if(Probe.calls!=1||Probe.commands!=1)throw new AssertionError("valid dispatch");
  // A0 uses the selected basic channel, so the root runtime must reject its CLA.
  check(s.transmitCommand(new byte[]{(byte)0xA0,1,0,0}),0x6E,0);
  if(Probe.calls!=1||Probe.commands!=2)throw new AssertionError("wrong CLA route/effect");
  // B1 selects unopened channel1: simulator rejection precedes AppletBase.
  check(s.transmitCommand(new byte[]{(byte)0xB1,1,0,0}),0x68,0x81);
  if(Probe.calls!=1||Probe.commands!=2)throw new AssertionError("closed channel reached applet");
  check(s.transmitCommand(new byte[]{(byte)0xB0,2,0,0}),0x6D,0);
  if(Probe.calls!=1||Probe.commands!=3)throw new AssertionError("unknown INS route/effect");
  check(s.transmitCommand(new byte[]{(byte)0xB0,1,0,0}),0x12,0x34,0x90,0);
  if(Probe.calls!=2||Probe.commands!=4)throw new AssertionError("lost recovery");
  System.out.println("root runtime controls passed");
 }
}
`
