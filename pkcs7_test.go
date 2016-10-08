package pkcs7

import (
	"bytes"
	"testing"
)

type (
	vector struct {
		in  []byte
		out []byte
	}
	errorVector struct {
		in  []byte
		out error
	}
)

var (
	blockSize = 4
	vectors   = []vector{
		{
			// len(in) < blockSize (expecting 2 padding bytes with a value of 0x2)
			in:  []byte{0x19, 0xC9},
			out: []byte{0x19, 0xC9, 0x2, 0x2},
		},
		{
			// len(in) > blockSize (expecting 3 padding bytes with a value of 0x3)
			in:  []byte{0x19, 0xC9, 0x8E, 0xAB, 0x19},
			out: []byte{0x19, 0xC9, 0x8E, 0xAB, 0x19, 0x3, 0x3, 0x3},
		},
		{
			// len(in) == blockSize (expecting 'blockSize' padding bytes with a value of 'blockSize')
			in:  []byte{0x19, 0xC9, 0x8E, 0xAB},
			out: []byte{0x19, 0xC9, 0x8E, 0xAB, 0x4, 0x4, 0x4, 0x4},
		},
		{
			// len(in) == 0 (expecting 'blockSize' padding bytes with a value of 'blockSize')
			in:  []byte{},
			out: []byte{0x4, 0x4, 0x4, 0x4},
		},
	}
	errorVectors = []errorVector{
		{
			// incorrect value; correct length
			in:  []byte{0x19, 0xC9, 0x3, 0x3},
			out: ErrPadding,
		},
		{
			// correct value; length too long
			in:  []byte{0x19, 0xC9, 0x2, 0x2, 0x2},
			out: ErrFullBlocks,
		},
		{
			// correct value; length too small
			in:  []byte{0x19, 0xC9, 0x2},
			out: ErrFullBlocks,
		},
		{
			// correct last value; rest of values incorrect; correct length
			in:  []byte{0x19, 0xC9, 0x3, 0x2},
			out: ErrPadding,
		},
	}
)

func TestPad(t *testing.T) {
	_, err := Pad(nil, 256)
	if err != ErrBlockSize {
		t.Errorf("expected: ErrBlockSize")
	}

	_, err = Pad(nil, 0)
	if err != ErrBlockSize {
		t.Errorf("expected: ErrBlockSize")
	}

	f := func(v vector) {
		out, err := Pad(v.in, blockSize)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(v.out, out) {
			t.Errorf("expected: %x, got: %x", v.out, out)
		}
	}

	for _, v := range vectors {
		f(v)
	}
}

func TestUnpad(t *testing.T) {
	_, err := Unpad(nil, 256)
	if err != ErrBlockSize {
		t.Errorf("expected: ErrBlockSize")
	}

	_, err = Unpad(nil, 0)
	if err != ErrBlockSize {
		t.Errorf("expected: ErrBlockSize")
	}

	for _, v := range vectors {
		out, err := Unpad(v.out, blockSize)
		if err != nil {
			t.Error(err)
			continue
		}

		if !bytes.Equal(v.in, out) {
			t.Errorf("expected: %x, got: %x", v.in, out)
		}
	}

	for _, v := range errorVectors {
		_, err := Unpad(v.in, blockSize)
		if err != v.out {
			t.Errorf("unexpected error")
		}
	}
}
