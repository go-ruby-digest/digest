// Copyright (c) the go-ruby-digest/digest authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package digest is a pure-Go (no cgo) reimplementation of Ruby's Digest
// standard library — the deterministic, interpreter-independent message-digest
// core of MRI 4.0.5's digest, digest/md5, digest/sha1, digest/sha2,
// digest/rmd160 and digest/bubblebabble.
//
// Each algorithm (MD5, SHA1, SHA256, SHA384, SHA512, RMD160) is exposed as an
// incremental [Digest] — an accumulating hasher fed through Update and read with
// Finish / HexFinish / Base64Finish — mirroring Ruby's Digest::Instance
// protocol (#update / #<< / #digest / #hexdigest / #base64digest / #reset). The
// class-level one-shots Digest::SHA256.digest(s) / .hexdigest(s) /
// .base64digest(s) map to [Sum] / [HexSum] / [Base64Sum], and the
// digest/bubblebabble extension maps to [BubbleBabble].
//
// The computation is backed by Go's crypto/* (MD5/SHA1/SHA2) and
// golang.org/x/crypto/ripemd160 (RMD160) — both pure Go — so every digest is
// byte-identical to MRI's, with no Ruby runtime and no cgo. The one-shot and
// finish paths sum and hex/Base64-encode through stack buffers so a full
// hexdigest allocates only its result string (see fastSum / hexEncode). It is
// the digest backend for go-embedded-ruby, but is a standalone, reusable module,
// a sibling of go-ruby-regexp (the Onigmo engine), go-ruby-erb (the ERB
// compiler) and go-ruby-yaml (the Psych emitter/loader).
package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

// Digest is an incremental message-digest hasher, the Go analogue of Ruby's
// Digest::Instance protocol. Update feeds bytes (Digest::Instance#update / #<<),
// Reset returns the hasher to its initial state (#reset), and the three Finish
// methods read the running digest in binary, hex and Base64 form (#digest,
// #hexdigest, #base64digest). Reading the digest does not reset it, matching
// MRI's no-argument finalizers.
type Digest interface {
	// Update appends data to the message being digested.
	Update(data []byte)
	// Reset discards the accumulated state, as if freshly constructed.
	Reset()
	// Finish returns the binary digest of the bytes fed so far.
	Finish() []byte
	// HexFinish returns the lowercase hexadecimal digest.
	HexFinish() string
	// Base64Finish returns the standard-Base64 (padded) digest.
	Base64Finish() string
	// BlockLength is the algorithm's internal block size in bytes
	// (Digest::Instance#block_length).
	BlockLength() int
	// DigestLength is the size of the produced digest in bytes
	// (Digest::Instance#digest_length / #length / #size).
	DigestLength() int
}

// algo describes one supported digest algorithm: how to build a fresh hasher and
// its fixed block size. The block size cannot be read back from hash.Hash for
// every algorithm uniformly, so it is recorded here to match MRI exactly.
type algo struct {
	newHash func() hash.Hash
	block   int
}

// algos maps a canonical MRI algorithm name (as used by Digest::MD5,
// Digest::SHA256, …) to its constructor and block length. RMD160 is the MRI
// spelling of RIPEMD-160 (Digest::RMD160).
var algos = map[string]algo{
	"MD5":    {md5.New, 64},
	"SHA1":   {sha1.New, 64},
	"SHA256": {sha256.New, 64},
	"SHA384": {sha512.New384, 128},
	"SHA512": {sha512.New, 128},
	"RMD160": {ripemd160.New, 64},
}

// maxDigest is the largest binary digest any supported algorithm produces
// (SHA-512 / RMD160 / … all ≤ 64 bytes). Stack buffers sized to it let the
// one-shot and finish paths sum-and-encode without a heap allocation for the
// digest itself. maxHex / maxB64 are the matching worst-case encoded sizes.
const (
	maxDigest = 64
	maxHex    = 2 * maxDigest             // hex.EncodedLen(64) = 128
	maxB64    = ((maxDigest + 2) / 3) * 4 // base64 padded len of 64 = 88
)

// fastSum computes the one-shot binary digest of data for a built-in crypto
// algorithm (identified by its canonical key), returning it in a fixed
// maxDigest-byte array plus its true length. Because md5.Sum / sha1.Sum /
// sha256.Sum256 / sha512.Sum384 / sha512.Sum512 each return their result in a
// value array, escape analysis keeps out on the caller's stack: the digest is
// produced with zero heap allocation, and the accompanying hasher object the
// streaming path allocates is avoided entirely. ok is false for RMD160 (which
// x/crypto exposes no array one-shot for) and for any unrecognised key, telling
// the caller to fall back to the streaming hasher. The bytes are identical to
// the streaming path — this only changes how they are produced, never what.
func fastSum(key string, data []byte) (out [maxDigest]byte, n int, ok bool) {
	switch key {
	case "MD5":
		s := md5.Sum(data)
		n = copy(out[:], s[:])
	case "SHA1":
		s := sha1.Sum(data)
		n = copy(out[:], s[:])
	case "SHA256":
		s := sha256.Sum256(data)
		n = copy(out[:], s[:])
	case "SHA384":
		s := sha512.Sum384(data)
		n = copy(out[:], s[:])
	case "SHA512":
		s := sha512.Sum512(data)
		n = copy(out[:], s[:])
	default:
		return out, 0, false
	}
	return out, n, true
}

// hexEncode hex-encodes a binary digest (≤ maxDigest bytes) into a stack buffer,
// allocating only the returned string. It is the shared encoder for the
// streaming finish path and the RMD160 one-shot fallback; the crypto one-shots
// inline the same two lines so the digest array stays on their own stack (a
// helper call would leak it to the heap).
func hexEncode(sum []byte) string {
	var hb [maxHex]byte
	n := hex.Encode(hb[:], sum)
	return string(hb[:n])
}

// base64Encode Base64-encodes a binary digest (≤ maxDigest bytes) into a stack
// buffer, allocating only the returned string — the Base64 analogue of
// hexEncode.
func base64Encode(sum []byte) string {
	var bb [maxB64]byte
	base64.StdEncoding.Encode(bb[:], sum)
	return string(bb[:base64.StdEncoding.EncodedLen(len(sum))])
}

// digest is the concrete incremental hasher returned by every constructor. It
// keeps the live hash.Hash plus the recipe needed to rebuild it on Reset.
type digest struct {
	a algo
	h hash.Hash
}

func (d *digest) Update(data []byte) { d.h.Write(data) }
func (d *digest) Reset()             { d.h = d.a.newHash() }
func (d *digest) Finish() []byte     { return d.h.Sum(nil) }
func (d *digest) BlockLength() int   { return d.a.block }
func (d *digest) DigestLength() int  { return d.a.newHash().Size() }

// HexFinish reads the running digest and hex-encodes it. The binary digest is
// summed into a stack array (no digest one exceeds 64 bytes) and hex-encoded into
// a second stack buffer, so the heap sees only the interface-forced Sum slice and
// the returned string — versus the three allocations the naive
// hex.EncodeToString(h.Sum(nil)) pair used to make.
func (d *digest) HexFinish() string {
	var db [maxDigest]byte
	return hexEncode(d.h.Sum(db[:0]))
}

// Base64Finish reads the running digest and Base64-encodes it, with the same
// single-allocation, stack-buffered strategy as HexFinish.
func (d *digest) Base64Finish() string {
	var db [maxDigest]byte
	return base64Encode(d.h.Sum(db[:0]))
}

// canonical normalises an algorithm name the way both Digest and OpenSSL accept
// it: case-insensitive and tolerant of the dashed spelling ("SHA-256", "sha1").
// RIPEMD160 / RIPEMD-160 are accepted as aliases for the MRI name RMD160.
func canonical(name string) string {
	key := strings.ToUpper(strings.ReplaceAll(name, "-", ""))
	switch key {
	case "RIPEMD160":
		return "RMD160"
	default:
		return key
	}
}

// New returns a fresh incremental [Digest] for an MRI algorithm name
// ("MD5", "SHA1", "SHA256", "SHA384", "SHA512", "RMD160"). It is the
// Digest(name) factory; an unknown name returns an error.
func New(name string) (Digest, error) {
	a, ok := algos[canonical(name)]
	if !ok {
		return nil, fmt.Errorf("digest: unknown algorithm %q", name)
	}
	return &digest{a: a, h: a.newHash()}, nil
}

// must builds a Digest for a name known to be valid (used by the direct
// constructors); it panics on an unknown name, which the constructors never pass.
func must(name string) Digest {
	d, err := New(name)
	if err != nil {
		panic(err)
	}
	return d
}

// MD5 returns a fresh Digest::MD5 hasher.
func MD5() Digest { return must("MD5") }

// SHA1 returns a fresh Digest::SHA1 hasher.
func SHA1() Digest { return must("SHA1") }

// SHA256 returns a fresh Digest::SHA256 hasher.
func SHA256() Digest { return must("SHA256") }

// SHA384 returns a fresh Digest::SHA384 hasher.
func SHA384() Digest { return must("SHA384") }

// SHA512 returns a fresh Digest::SHA512 hasher.
func SHA512() Digest { return must("SHA512") }

// RMD160 returns a fresh Digest::RMD160 (RIPEMD-160) hasher.
func RMD160() Digest { return must("RMD160") }

// Sum is the binary class one-shot Digest::ALGO.digest(data): the raw digest of
// data under the named algorithm. For the built-in crypto algorithms it uses the
// allocation-free stack hasher (fastSum), copying out only the exact-length
// result slice it must return; RMD160 falls back to the streaming hasher.
func Sum(name string, data []byte) ([]byte, error) {
	a, ok := algos[canonical(name)]
	if !ok {
		return nil, fmt.Errorf("digest: unknown algorithm %q", name)
	}
	if d, n, fast := fastSum(canonical(name), data); fast {
		return append([]byte(nil), d[:n]...), nil
	}
	h := a.newHash()
	h.Write(data)
	return h.Sum(nil), nil
}

// HexSum is the class one-shot Digest::ALGO.hexdigest(data). This is the exact
// Go analogue of Ruby's Digest::SHA256.hexdigest(s) — the hot path the parity
// benchmark exercises. For the crypto algorithms it sums into a stack array and
// hex-encodes (inline, so the array never escapes) into a second stack buffer,
// leaving the returned string as the sole allocation.
func HexSum(name string, data []byte) (string, error) {
	key := canonical(name)
	if _, ok := algos[key]; !ok {
		return "", fmt.Errorf("digest: unknown algorithm %q", name)
	}
	if d, n, fast := fastSum(key, data); fast {
		var hb [maxHex]byte
		m := hex.Encode(hb[:], d[:n])
		return string(hb[:m]), nil
	}
	h := algos[key].newHash()
	h.Write(data)
	return hexEncode(h.Sum(nil)), nil
}

// Base64Sum is the class one-shot Digest::ALGO.base64digest(data), with the same
// stack-buffered single-allocation strategy as HexSum.
func Base64Sum(name string, data []byte) (string, error) {
	key := canonical(name)
	if _, ok := algos[key]; !ok {
		return "", fmt.Errorf("digest: unknown algorithm %q", name)
	}
	if d, n, fast := fastSum(key, data); fast {
		var bb [maxB64]byte
		base64.StdEncoding.Encode(bb[:], d[:n])
		return string(bb[:base64.StdEncoding.EncodedLen(n)]), nil
	}
	h := algos[key].newHash()
	h.Write(data)
	return base64Encode(h.Sum(nil)), nil
}

// SumFile is the class one-shot Digest::ALGO.file(path): the binary digest of a
// file's contents. The returned bytes match Digest::ALGO.file(path).digest.
func SumFile(name, path string) ([]byte, error) {
	a, ok := algos[canonical(name)]
	if !ok {
		return nil, fmt.Errorf("digest: unknown algorithm %q", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sumReader(a, f)
}

// sumReader streams r through a fresh hasher for algo a, returning the binary
// digest. Split out from SumFile so the read-error path is testable with a
// failing reader (a directory or pipe can read-fault mid-stream).
func sumReader(a algo, r io.Reader) ([]byte, error) {
	h := a.newHash()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// HexSumFile is Digest::ALGO.file(path).hexdigest.
func HexSumFile(name, path string) (string, error) {
	b, err := SumFile(name, path)
	if err != nil {
		return "", err
	}
	return hexEncode(b), nil
}

// Base64SumFile is Digest::ALGO.file(path).base64digest.
func Base64SumFile(name, path string) (string, error) {
	b, err := SumFile(name, path)
	if err != nil {
		return "", err
	}
	return base64Encode(b), nil
}

// bubbleVowels and bubbleConsonants are the alphabets of the Bubble Babble
// encoding (Antti Huima), exactly as MRI's digest/bubblebabble uses them.
const (
	bubbleVowels     = "aeiouy"
	bubbleConsonants = "bcdfghklmnprstvzx"
)

// BubbleBabble encodes data with the Bubble Babble algorithm, the deterministic
// pronounceable digest format used by Digest.bubblebabble. The output begins and
// ends with 'x' and reads as a string of CV/CVC tuples separated by hyphens —
// the same bytes MRI emits.
func BubbleBabble(data []byte) string {
	var b strings.Builder
	seed := 1
	b.WriteByte('x')
	rounds := len(data)/2 + 1
	for i := 0; i < rounds; i++ {
		if i+1 < rounds || len(data)%2 != 0 {
			idx0 := (((int(data[2*i]) >> 6) & 3) + seed) % 6
			idx1 := (int(data[2*i]) >> 2) & 15
			idx2 := ((int(data[2*i]) & 3) + seed/6) % 6
			b.WriteByte(bubbleVowels[idx0])
			b.WriteByte(bubbleConsonants[idx1])
			b.WriteByte(bubbleVowels[idx2])
			if i+1 < rounds {
				idx3 := (int(data[2*i+1]) >> 4) & 15
				idx4 := int(data[2*i+1]) & 15
				b.WriteByte(bubbleConsonants[idx3])
				b.WriteByte('-')
				b.WriteByte(bubbleConsonants[idx4])
				seed = (seed*5 + int(data[2*i])*7 + int(data[2*i+1])) % 36
			}
		} else {
			idx0 := seed % 6
			idx1 := 16
			idx2 := seed / 6
			b.WriteByte(bubbleVowels[idx0])
			b.WriteByte(bubbleConsonants[idx1])
			b.WriteByte(bubbleVowels[idx2])
		}
	}
	b.WriteByte('x')
	return b.String()
}

// SumBubbleBabble is the class/instance one-shot Digest::ALGO.bubblebabble(data)
// and #bubblebabble: the Bubble Babble encoding of the algorithm's binary digest
// of data (not of data itself).
func SumBubbleBabble(name string, data []byte) (string, error) {
	b, err := Sum(name, data)
	if err != nil {
		return "", err
	}
	return BubbleBabble(b), nil
}
