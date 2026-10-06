package codegen

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The unchanged root runtime is exercised through Simulator.transmitCommand ->
// AppletBase.process: valid dispatch and response, wrong CLA without dispatch,
// and unknown INS without a handler effect. This does not open a physical card.
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
  static int calls;
  public Probe(){super((byte)0xB0);}
  public static void install(byte[] b,short o,byte l){new Probe().register();}
  protected void dispatch(APDU a,byte ins){
   if(ins!=(byte)1)ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
   calls++;sendU16(a,(short)0x1234);
  }
 }
 static void check(byte[] got,int...want){if(got.length!=want.length)throw new AssertionError("response length");for(int i=0;i<want.length;i++)if((got[i]&255)!=want[i])throw new AssertionError("response byte "+i);}
 public static void main(String[]args){
  Simulator s=new Simulator();AID aid=new AID(new byte[]{(byte)0xF0,0,0,1,2,1},(short)0,(byte)6);
  s.installApplet(aid,Probe.class);s.selectApplet(aid);
  check(s.transmitCommand(new byte[]{(byte)0xB0,1,0,0}),0x12,0x34,0x90,0);
  if(Probe.calls!=1)throw new AssertionError("valid dispatch");
  check(s.transmitCommand(new byte[]{(byte)0xB1,1,0,0}),0x6E,0);
  if(Probe.calls!=1)throw new AssertionError("wrong CLA dispatched");
  check(s.transmitCommand(new byte[]{(byte)0xB0,2,0,0}),0x6D,0);
  if(Probe.calls!=1)throw new AssertionError("unknown INS effect");
  check(s.transmitCommand(new byte[]{(byte)0xB0,1,0,0}),0x12,0x34,0x90,0);
  if(Probe.calls!=2)throw new AssertionError("lost recovery");
  System.out.println("root runtime controls passed");
 }
}
`
