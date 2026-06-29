// Copyright (c) the go-ruby-digest/digest authors
//
// SPDX-License-Identifier: BSD-3-Clause

package digest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// rubyBin locates a usable `ruby` once and gates the oracle on MRI >= 4.0 (the
// digest/bubblebabble surface and 4.0.5 byte answers). It skips itself when ruby
// is absent (the qemu cross-arch lanes and the Windows lane) so the deterministic
// suite alone drives the 100% gate there.
func rubyBin(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping MRI oracle")
	}
	out, err := exec.Command(path, "-e", "print RUBY_VERSION").CombinedOutput()
	if err != nil {
		t.Skipf("ruby -e failed (%v); skipping MRI oracle", err)
	}
	ver := strings.TrimSpace(string(out))
	major, _, _ := strings.Cut(ver, ".")
	if n, err := strconv.Atoi(major); err != nil || n < 4 {
		t.Skipf("ruby %s < 4.0; skipping MRI oracle", ver)
	}
	return path
}

// rubyEval runs a Ruby script under the digest libraries and returns its stdout.
// The preamble $stdout.binmode-s and $stdin.binmode-s so Windows text-mode never
// pollutes the bytes (the go-ruby-erb lesson).
func rubyEval(t *testing.T, bin, script string) string {
	t.Helper()
	preamble := "$stdout.binmode\n$stdin.binmode\nrequire 'digest'\nrequire 'digest/bubblebabble'\nrequire 'digest/sha2'\n"
	cmd := exec.Command(bin, "-e", preamble+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return string(out)
}

// corpus is the differential message set: each is fed to MRI and to this package
// and the outputs must match byte-for-byte. It spans empty, ascii, binary, and
// multi-block inputs.
var corpus = []string{
	"",
	"a",
	"abc",
	"message digest",
	"The quick brown fox jumps over the lazy dog",
	"1234567890",
	"Pineapple",
	strings.Repeat("x", 1000),
	"\x00\x01\x02\xff\xfe\x80",
}

func TestOracleHexDigest(t *testing.T) {
	bin := rubyBin(t)
	for name := range algos {
		for _, in := range corpus {
			lit := strconv.Quote(in)
			script := "print Digest::" + name + ".hexdigest(" + lit + ")"
			want := rubyEval(t, bin, script)
			got, err := HexSum(name, []byte(in))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s.hexdigest(%q): got %q, MRI %q", name, in, got, want)
			}
		}
	}
}

func TestOracleBase64Digest(t *testing.T) {
	bin := rubyBin(t)
	for name := range algos {
		for _, in := range corpus {
			lit := strconv.Quote(in)
			want := rubyEval(t, bin, "print Digest::"+name+".base64digest("+lit+")")
			got, err := Base64Sum(name, []byte(in))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s.base64digest(%q): got %q, MRI %q", name, in, got, want)
			}
		}
	}
}

func TestOracleBinaryDigest(t *testing.T) {
	bin := rubyBin(t)
	for name := range algos {
		for _, in := range corpus {
			lit := strconv.Quote(in)
			// Print the raw digest as hex from MRI so the transport is text-safe.
			want := rubyEval(t, bin, "print Digest::"+name+".digest("+lit+").unpack1('H*')")
			got, err := Sum(name, []byte(in))
			if err != nil {
				t.Fatal(err)
			}
			if hexOf(got) != want {
				t.Errorf("%s.digest(%q): got %x, MRI %s", name, in, got, want)
			}
		}
	}
}

func TestOracleBubbleBabble(t *testing.T) {
	bin := rubyBin(t)
	for _, in := range corpus {
		lit := strconv.Quote(in)
		want := rubyEval(t, bin, "print Digest.bubblebabble("+lit+")")
		if got := BubbleBabble([]byte(in)); got != want {
			t.Errorf("bubblebabble(%q): got %q, MRI %q", in, got, want)
		}
	}
}

func TestOracleClassBubbleBabble(t *testing.T) {
	bin := rubyBin(t)
	for name := range algos {
		for _, in := range corpus {
			lit := strconv.Quote(in)
			want := rubyEval(t, bin, "print Digest::"+name+".bubblebabble("+lit+")")
			got, err := SumBubbleBabble(name, []byte(in))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s.bubblebabble(%q): got %q, MRI %q", name, in, got, want)
			}
		}
	}
}

func TestOracleLengths(t *testing.T) {
	bin := rubyBin(t)
	for name := range algos {
		want := rubyEval(t, bin,
			"d=Digest::"+name+".new; print [d.block_length, d.digest_length, d.length, d.size].inspect")
		d, _ := New(name)
		got := "[" + strconv.Itoa(d.BlockLength()) + ", " +
			strconv.Itoa(d.DigestLength()) + ", " +
			strconv.Itoa(d.DigestLength()) + ", " +
			strconv.Itoa(d.DigestLength()) + "]"
		if got != want {
			t.Errorf("%s lengths: got %s, MRI %s", name, got, want)
		}
	}
}

func TestOracleSHA2Bitlen(t *testing.T) {
	bin := rubyBin(t)
	// Digest::SHA2.new(bitlen) selects the SHA-256/384/512 variant; map to ours.
	pairs := []struct {
		bitlen int
		name   string
	}{{256, "SHA256"}, {384, "SHA384"}, {512, "SHA512"}}
	for _, p := range pairs {
		want := rubyEval(t, bin,
			"print Digest::SHA2.new("+strconv.Itoa(p.bitlen)+").hexdigest('abc')")
		got, _ := HexSum(p.name, []byte("abc"))
		if got != want {
			t.Errorf("SHA2(%d).hexdigest(abc): got %q, MRI %q", p.bitlen, got, want)
		}
	}
}

func TestOracleIncrementalUpdate(t *testing.T) {
	bin := rubyBin(t)
	// Feed the input in three chunks through update/<< and compare to MRI doing
	// the same, proving incremental state matches the one-shot path.
	for name := range algos {
		want := rubyEval(t, bin,
			"d=Digest::"+name+".new; d.update('foo'); d << 'bar'; d.update('baz'); print d.hexdigest")
		d, _ := New(name)
		d.Update([]byte("foo"))
		d.Update([]byte("bar"))
		d.Update([]byte("baz"))
		if got := d.HexFinish(); got != want {
			t.Errorf("%s incremental: got %q, MRI %q", name, got, want)
		}
	}
}

func TestOracleFile(t *testing.T) {
	bin := rubyBin(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	content := []byte("the quick brown fox\x00\x01\x02 jumps")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	slash := filepath.ToSlash(path)
	for name := range algos {
		want := rubyEval(t, bin,
			"print Digest::"+name+".file("+strconv.Quote(slash)+").hexdigest")
		got, err := HexSumFile(name, path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s.file: got %q, MRI %q", name, got, want)
		}
	}
}

// hexOf is a tiny local hex encoder kept here so the oracle file is independent
// of the package's encoding/hex import for readability.
func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}
