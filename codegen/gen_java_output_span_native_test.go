package codegen

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeOrdinaryNativeFixture(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "src", "io", "jcrpc", "writer")
	r := writerResult(t)
	for name, source := range map[string][]byte{r.TransportName: r.TransportSource, r.SkeletonName: r.SkeletonSource} {
		writeTestFile(t, filepath.Join(dir, name+".java"), source)
	}
	fixture, err := os.ReadFile("testdata/OrdinaryOutputSpanApplet.java")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "OrdinaryOutputSpanApplet.java"), fixture)
	return dir
}

// Real Simulator.transmitCommand -> Applet.process -> generated dispatchTo sends
// only produced bytes from a nonzero offset, including same-buffer echo/typed
// requests. Handler-return/request/routing refusals send only SW and recover.
// Simulator buffer capacity is not a physical-card or minimum-133B capacity claim.
func TestGeneratedOrdinaryOutputSpanRealSimulator(t *testing.T) {
	jar := simulatorJar(t)
	root := t.TempDir()
	dir := writeOrdinaryNativeFixture(t, root)
	writeTestFile(t, filepath.Join(dir, "OrdinaryAPDUHarness.java"), []byte(ordinaryAPDUHarness))
	sources, err := filepath.Glob(filepath.Join(dir, "*.java"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := exec.Command("javac", append([]string{"-cp", jar, "-d", root}, sources...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ordinary simulator compile: %v\n%s", err, b)
	}
	b, err = exec.Command("java", "-cp", root+string(os.PathListSeparator)+jar, "io.jcrpc.writer.OrdinaryAPDUHarness").CombinedOutput()
	if err != nil {
		t.Fatalf("ordinary simulator: %v\n%s", err, b)
	}
	if !strings.Contains(string(b), "ordinary APDU controls passed") {
		t.Fatalf("missing control: %s", b)
	}
	t.Log(string(b))
}

// Oracle Classic conversion/verification covers all four writer widths, short
// indexed borrowed requests, overlap helpers, scalar/void packing and the caller
// send site. This proves CAP acceptance, not physical installation or RAM/NVM.
func TestGeneratedOrdinaryOutputSpanClassicCAP(t *testing.T) {
	ant, err := exec.LookPath("ant")
	if err != nil {
		t.Fatal(err)
	}
	jar, kit := os.Getenv("JCRPC_ANT_JAVACARD_JAR"), os.Getenv("JCRPC_JCKIT_DIR")
	if jar == "" || kit == "" {
		t.Skip("set CAP toolchain variables")
	}
	root := t.TempDir()
	writeOrdinaryNativeFixture(t, root)
	capPath := filepath.Join(root, "writer.cap")
	build := fmt.Sprintf(`<project name="ordinary-writer-cap" default="cap">
      <taskdef name="javacard" classname="pro.javacard.ant.JavaCard" classpath="%s"/>
      <target name="cap"><javacard><cap jckit="%s" sources="%s"
        package="io.jcrpc.writer" aid="F000000103" version="1.0" ints="true" output="%s">
        <applet class="io.jcrpc.writer.OrdinaryOutputSpanApplet" aid="F00000010301"/>
      </cap></javacard></target></project>`, jar, kit, filepath.Join(root, "src"), capPath)
	buildPath := filepath.Join(root, "build.xml")
	writeTestFile(t, buildPath, []byte(build))
	b, err := exec.Command(ant, "-f", buildPath, "cap").CombinedOutput()
	if err != nil {
		t.Fatalf("ordinary Classic CAP: %v\n%s", err, b)
	}
	t.Log(string(b))
	z, err := zip.OpenReader(capPath)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var components, methods uint64
	for _, f := range z.File {
		if strings.HasSuffix(f.Name, ".cap") {
			components += f.UncompressedSize64
		}
		if strings.HasSuffix(f.Name, "/Method.cap") {
			methods = f.UncompressedSize64
		}
	}
	if components == 0 || methods == 0 {
		t.Fatal("missing CAP components")
	}
	b, err = os.ReadFile(capPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ordinary CAP components=%d B; Method.cap=%d B; ZIP=%d B; SHA256=%x", components, methods, len(b), sha256.Sum256(b))
}

const ordinaryAPDUHarness = `package io.jcrpc.writer;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.*;
import java.util.Arrays;
public final class OrdinaryAPDUHarness {
    static Simulator simulator;
    static byte[] send(int ins, int p1, byte[] data) {
        byte[] command=new byte[data.length==0?4:5+data.length];
        command[0]=(byte)0x80;command[1]=(byte)ins;command[2]=(byte)p1;
        if(data.length>0){command[4]=(byte)data.length;System.arraycopy(data,0,command,5,data.length);}
        return simulator.transmitCommand(command);
    }
    static void require(boolean b,String witness){if(!b)throw new AssertionError(witness);}
    static void testFixedAPDUWire(){
        int[] widths={127,13,190,177};
        for(int ins=1;ins<=4;ins++){
            byte[] r=send(ins,0,new byte[0]);int n=widths[ins-1];
            require(r.length==n+2,"testFixedAPDUWire length");
            for(int i=0;i<n;i++)require(r[i]==(byte)(i+ins),"testFixedAPDUWire span");
            require(r[n]==(byte)0x90 && r[n+1]==0,"testFixedAPDUWire status");
        }
    }
    static void testFailureDoesNotTransmit(){
        for(int mode=1;mode<=3;mode++)require(Arrays.equals(send(1,mode,new byte[0]),new byte[]{0x67,0}),"testFailureDoesNotTransmit produced");
        require(Arrays.equals(send(127,0,new byte[0]),new byte[]{0x6D,0}),"testFailureDoesNotTransmit INS");
        require(Arrays.equals(send(11,0,new byte[7]),new byte[]{0x67,0}),"testFailureDoesNotTransmit request");
        require(Arrays.equals(send(9,0,new byte[0]),new byte[]{(byte)0x90,0}),"testFailureDoesNotTransmit recovery");
        testFixedAPDUWire();
    }
    static void testSameBufferOverlap(){
        require(Arrays.equals(send(11,0,new byte[]{0x12,0x34,1,2,3,4}),new byte[]{1,2,0x11,0x30,(byte)0x90,0}),"testSameBufferOverlap typed");
        require(Arrays.equals(send(10,0,new byte[]{0,3,11,22,33}),new byte[]{11,22,33,(byte)0x90,0}),"testSameBufferOverlap borrowed");
    }
    public static void main(String[] args){
        simulator=new Simulator();AID aid=new AID(new byte[]{(byte)0xF0,0,0,1,3,1},(short)0,(byte)6);
        simulator.installApplet(aid,OrdinaryOutputSpanApplet.class);simulator.selectApplet(aid);
        testFixedAPDUWire();testFailureDoesNotTransmit();testSameBufferOverlap();
        System.out.println("ordinary APDU controls passed");
    }
}
`
