<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-digest/brand/main/social/go-ruby-digest-digest.png" alt="go-ruby-digest/digest" width="720"></p>

# digest — go-ruby-digest

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-digest.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [Digest](https://docs.ruby-lang.org/en/master/Digest.html)
standard library** — the deterministic, interpreter-independent message-digest core
of MRI 4.0.5's `digest`, `digest/md5`, `digest/sha1`, `digest/sha2`,
`digest/rmd160` and `digest/bubblebabble`. It computes `Digest::MD5` / `SHA1` /
`SHA256` / `SHA384` / `SHA512` / `RMD160` and the `Digest.bubblebabble` encoding
**byte-for-byte identical to MRI**, with no Ruby runtime and no cgo.

It is the digest backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp) (the Onigmo engine),
[go-ruby-erb](https://github.com/go-ruby-erb/erb) (the ERB compiler) and
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml) (the Psych emitter/loader).

> **What it is — and isn't.** A message digest is pure computation over bytes, so
> it lives here as pure Go over `crypto/*` and `golang.org/x/crypto/ripemd160`.
> Binding the algorithms into Ruby classes (`Digest::SHA256`, the `#update` /
> `#hexdigest` protocol, `==` against a hex string) is the host's job; this
> library hands back a small, idiomatic Go [`Digest`](#api) interface plus
> one-shot helpers the host maps onto MRI's surface.

## Features

Faithful port of MRI's Digest, validated against the `ruby` binary on every
supported platform:

- **Six algorithms** — `MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`, `RMD160`
  (RIPEMD-160), each with its correct block and digest lengths.
- **Incremental protocol** — `Update` / `Reset` / `Finish` / `HexFinish` /
  `Base64Finish` mirror `Digest::Instance#update` / `#<<` / `#reset` / `#digest`
  / `#hexdigest` / `#base64digest`.
- **Class one-shots** — `Sum` / `HexSum` / `Base64Sum` are
  `Digest::ALGO.digest` / `.hexdigest` / `.base64digest`; `SumFile` /
  `HexSumFile` / `Base64SumFile` are `Digest::ALGO.file(path)`.
- **Bubble Babble** — `BubbleBabble` is `Digest.bubblebabble` (the Antti Huima
  pronounceable encoding); `SumBubbleBabble` is `Digest::ALGO.bubblebabble`
  (bubble-babble of the algorithm's digest), matching MRI's `digest/bubblebabble`.
- **Name factory** — `New("SHA256")` is the `Digest(name)` factory, case- and
  dash-insensitive (`"sha-256"`), with `RIPEMD160` aliased to `RMD160`.

CGO-free, **100% test coverage**, `gofmt` + `go vet` clean, and green across the
six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le, s390x).

## Install

```sh
go get github.com/go-ruby-digest/digest
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-digest/digest"
)

func main() {
	// One-shot: Digest::SHA256.hexdigest("abc")
	hx, _ := digest.HexSum("SHA256", []byte("abc"))
	fmt.Println(hx) // ba7816bf...20015ad

	// Incremental: Digest::SHA1.new; d.update("a"); d << "bc"; d.hexdigest
	d := digest.SHA1()
	d.Update([]byte("a"))
	d.Update([]byte("bc"))
	fmt.Println(d.HexFinish()) // a9993e36...7850c26c9cd0d89d

	// Digest.bubblebabble("Pineapple")
	fmt.Println(digest.BubbleBabble([]byte("Pineapple"))) // xigak-nyryk-humil-bosek-sonax
}
```

## API

```go
// Digest is the incremental Digest::Instance protocol.
type Digest interface {
	Update(data []byte)    // #update / #<<
	Reset()                // #reset
	Finish() []byte        // #digest
	HexFinish() string     // #hexdigest
	Base64Finish() string  // #base64digest
	BlockLength() int      // #block_length
	DigestLength() int     // #digest_length / #length / #size
}

// New is the Digest(name) factory; the direct constructors are the named classes.
func New(name string) (Digest, error)
func MD5() Digest
func SHA1() Digest
func SHA256() Digest
func SHA384() Digest
func SHA512() Digest
func RMD160() Digest

// Class one-shots: Digest::ALGO.digest / .hexdigest / .base64digest.
func Sum(name string, data []byte) ([]byte, error)
func HexSum(name string, data []byte) (string, error)
func Base64Sum(name string, data []byte) (string, error)

// File one-shots: Digest::ALGO.file(path).{digest,hexdigest,base64digest}.
func SumFile(name, path string) ([]byte, error)
func HexSumFile(name, path string) (string, error)
func Base64SumFile(name, path string) (string, error)

// Bubble Babble: Digest.bubblebabble and Digest::ALGO.bubblebabble.
func BubbleBabble(data []byte) string
func SumBubbleBabble(name string, data []byte) (string, error)
```

## Algorithm table

| MRI class        | `name`     | block | digest | backend                          |
| ---------------- | ---------- | ----- | ------ | -------------------------------- |
| `Digest::MD5`    | `"MD5"`    | 64    | 16     | `crypto/md5`                     |
| `Digest::SHA1`   | `"SHA1"`   | 64    | 20     | `crypto/sha1`                    |
| `Digest::SHA256` | `"SHA256"` | 64    | 32     | `crypto/sha256`                  |
| `Digest::SHA384` | `"SHA384"` | 128   | 48     | `crypto/sha512`                  |
| `Digest::SHA512` | `"SHA512"` | 128   | 64     | `crypto/sha512`                  |
| `Digest::RMD160` | `"RMD160"` | 64    | 20     | `golang.org/x/crypto/ripemd160`  |

## Tests & coverage

The suite pairs deterministic, ruby-free tests (which alone hold coverage at
100%, so the qemu cross-arch and Windows lanes pass the gate) with a
**differential MRI oracle**: a corpus is hashed here and by the system `ruby`
(`Digest::ALGO.hexdigest` / `.base64digest` / `.digest` / `.bubblebabble` /
`.file`, the incremental `update`/`<<` path, and `SHA2.new(bitlen)`), and the
outputs must match byte-for-byte. The oracle scripts `$stdout.binmode` /
`$stdin.binmode` so Windows text-mode never pollutes the bytes, gate on MRI
`>= 4.0`, and skip themselves where `ruby` is absent; the `.file` test uses
`t.TempDir()` + `filepath.ToSlash` so no OS path is embedded in Ruby source.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-digest/digest authors.
