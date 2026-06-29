// Copyright (c) the go-ruby-digest/digest authors
//
// SPDX-License-Identifier: BSD-3-Clause

package digest

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These deterministic, ruby-free tests pin every digest to a known answer and
// exercise every branch, so they alone hold coverage at 100% on the no-ruby /
// qemu / Windows lanes; the MRI oracle in oracle_test.go cross-checks them.

// goldenHex are the canonical hexdigests of "abc" for each algorithm, taken from
// MRI 4.0.5 (ruby -rdigest -e 'Digest::ALGO.hexdigest("abc")').
var goldenHex = map[string]string{
	"MD5":    "900150983cd24fb0d6963f7d28e17f72",
	"SHA1":   "a9993e364706816aba3e25717850c26c9cd0d89d",
	"SHA256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"SHA384": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"SHA512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"RMD160": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
}

// wantBlock / wantDigest pin the block and digest lengths to MRI's
// (Digest::ALGO.new.block_length / .digest_length).
var wantBlock = map[string]int{"MD5": 64, "SHA1": 64, "SHA256": 64, "SHA384": 128, "SHA512": 128, "RMD160": 64}
var wantDigest = map[string]int{"MD5": 16, "SHA1": 20, "SHA256": 32, "SHA384": 48, "SHA512": 64, "RMD160": 20}

func TestHexFinishGolden(t *testing.T) {
	for name, want := range goldenHex {
		d, err := New(name)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		d.Update([]byte("abc"))
		if got := d.HexFinish(); got != want {
			t.Errorf("%s.HexFinish() = %q, want %q", name, got, want)
		}
	}
}

func TestDirectConstructors(t *testing.T) {
	ctors := map[string]func() Digest{
		"MD5": MD5, "SHA1": SHA1, "SHA256": SHA256,
		"SHA384": SHA384, "SHA512": SHA512, "RMD160": RMD160,
	}
	for name, ctor := range ctors {
		d := ctor()
		d.Update([]byte("abc"))
		if got := d.HexFinish(); got != goldenHex[name] {
			t.Errorf("%s() => %q, want %q", name, got, goldenHex[name])
		}
		if d.BlockLength() != wantBlock[name] {
			t.Errorf("%s block = %d, want %d", name, d.BlockLength(), wantBlock[name])
		}
		if d.DigestLength() != wantDigest[name] {
			t.Errorf("%s digest = %d, want %d", name, d.DigestLength(), wantDigest[name])
		}
	}
}

func TestFinishVariants(t *testing.T) {
	d := SHA256()
	d.Update([]byte("abc"))
	bin := d.Finish()
	if hex.EncodeToString(bin) != goldenHex["SHA256"] {
		t.Errorf("Finish() = %x", bin)
	}
	if d.HexFinish() != goldenHex["SHA256"] {
		t.Errorf("HexFinish() = %q", d.HexFinish())
	}
	wantB64 := base64.StdEncoding.EncodeToString(bin)
	if d.Base64Finish() != wantB64 {
		t.Errorf("Base64Finish() = %q, want %q", d.Base64Finish(), wantB64)
	}
	// MRI: Digest::SHA256.base64digest("abc")
	if d.Base64Finish() != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Errorf("Base64Finish() = %q, want golden", d.Base64Finish())
	}
}

func TestUpdateIncremental(t *testing.T) {
	d := SHA1()
	d.Update([]byte("a"))
	d.Update([]byte("b"))
	d.Update([]byte("c"))
	if got := d.HexFinish(); got != goldenHex["SHA1"] {
		t.Errorf("incremental SHA1 = %q, want %q", got, goldenHex["SHA1"])
	}
}

func TestReset(t *testing.T) {
	d := MD5()
	d.Update([]byte("abc"))
	d.Reset()
	// MRI: Digest::MD5.hexdigest("") of the empty string.
	if got := d.HexFinish(); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("after Reset, HexFinish() = %q, want empty-md5", got)
	}
	d.Update([]byte("abc"))
	if got := d.HexFinish(); got != goldenHex["MD5"] {
		t.Errorf("after Reset+Update, HexFinish() = %q", got)
	}
}

func TestNewAliases(t *testing.T) {
	for _, name := range []string{"sha256", "SHA-256", "Sha256"} {
		d, err := New(name)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		d.Update([]byte("abc"))
		if d.HexFinish() != goldenHex["SHA256"] {
			t.Errorf("New(%q) gave wrong digest", name)
		}
	}
	// RIPEMD-160 aliases for RMD160.
	for _, name := range []string{"RIPEMD160", "RIPEMD-160", "rmd160"} {
		d, err := New(name)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		d.Update([]byte("abc"))
		if d.HexFinish() != goldenHex["RMD160"] {
			t.Errorf("New(%q) gave wrong digest", name)
		}
	}
}

func TestNewUnknown(t *testing.T) {
	if _, err := New("SHA3"); err == nil {
		t.Fatal("New(SHA3) should error")
	}
}

func TestSumHelpers(t *testing.T) {
	bin, err := Sum("SHA256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bin) != goldenHex["SHA256"] {
		t.Errorf("Sum = %x", bin)
	}
	hx, err := HexSum("SHA256", []byte("abc"))
	if err != nil || hx != goldenHex["SHA256"] {
		t.Errorf("HexSum = %q, %v", hx, err)
	}
	b64, err := Base64Sum("SHA256", []byte("abc"))
	if err != nil || b64 != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Errorf("Base64Sum = %q, %v", b64, err)
	}
}

func TestSumHelpersUnknown(t *testing.T) {
	if _, err := Sum("NOPE", nil); err == nil {
		t.Error("Sum unknown should error")
	}
	if _, err := HexSum("NOPE", nil); err == nil {
		t.Error("HexSum unknown should error")
	}
	if _, err := Base64Sum("NOPE", nil); err == nil {
		t.Error("Base64Sum unknown should error")
	}
	if _, err := SumBubbleBabble("NOPE", nil); err == nil {
		t.Error("SumBubbleBabble unknown should error")
	}
}

func TestFileHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	// MRI: Digest::SHA256.file(path).hexdigest == hexdigest("hello world")
	wantHex := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	bin, err := SumFile("SHA256", path)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bin) != wantHex {
		t.Errorf("SumFile = %x", bin)
	}
	hx, err := HexSumFile("SHA256", path)
	if err != nil || hx != wantHex {
		t.Errorf("HexSumFile = %q, %v", hx, err)
	}
	b64, err := Base64SumFile("SHA256", path)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString(bin); b64 != want {
		t.Errorf("Base64SumFile = %q, want %q", b64, want)
	}
}

func TestFileHelpersErrors(t *testing.T) {
	// Unknown algorithm short-circuits before opening the file.
	if _, err := SumFile("NOPE", "whatever"); err == nil {
		t.Error("SumFile unknown algo should error")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := SumFile("SHA256", missing); err == nil {
		t.Error("SumFile missing file should error")
	}
	if _, err := HexSumFile("SHA256", missing); err == nil {
		t.Error("HexSumFile missing file should error")
	}
	if _, err := Base64SumFile("SHA256", missing); err == nil {
		t.Error("Base64SumFile missing file should error")
	}
}

// errReader fails on the first Read, exercising sumReader's io.Copy error path
// without depending on a platform-specific read-faulting file.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errFakeRead }

var errFakeRead = errors.New("fake read failure")

func TestSumReaderError(t *testing.T) {
	if _, err := sumReader(algos["SHA256"], errReader{}); err == nil {
		t.Fatal("sumReader should propagate read error")
	}
}

func TestBubbleBabbleGolden(t *testing.T) {
	// Digest.bubblebabble(s) for raw strings, from MRI.
	cases := map[string]string{
		"":           "xexax",
		"a":          "ximex",
		"ab":         "ximek-dixux",
		"abc":        "ximek-domex",
		"1234567890": "xesef-disof-gytuf-katof-movif-baxux",
		"Pineapple":  "xigak-nyryk-humil-bosek-sonax",
	}
	for in, want := range cases {
		if got := BubbleBabble([]byte(in)); got != want {
			t.Errorf("BubbleBabble(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSumBubbleBabble(t *testing.T) {
	// Digest::SHA1.bubblebabble("abc") == BubbleBabble(SHA1.digest("abc")).
	got, err := SumBubbleBabble("SHA1", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := "xopen-nozof-kaceb-kibek-povif-venel-cavih-babek-selet-bikon-tixox"
	if got != want {
		t.Errorf("SumBubbleBabble(SHA1,abc) = %q, want %q", got, want)
	}
}

// TestMustPanics covers the unreachable panic guard in must via a deliberately
// invalid name, proving the guard works without ever shipping a bad constructor.
func TestMustPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("must with bad name should panic")
		}
	}()
	_ = must("NOPE")
}

func TestNewError(t *testing.T) {
	_, err := New("bogus")
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("New error = %v", err)
	}
}
