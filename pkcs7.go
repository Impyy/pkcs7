// Package pkcs7 implements data padding as specified by the PKCS #7 standard. See
// also: https://tools.ietf.org/html/rfc5652#section-6.3.
package pkcs7

import (
	"errors"
	"fmt"
)

var (
	minBlockSize = 1
	maxBlockSize = 255

	ErrEmpty      = errors.New("the given byte slice is empty")
	ErrPadding    = errors.New("bad padding")
	ErrFullBlocks = errors.New("input not full blocks")
	ErrBlockSize  = fmt.Errorf("invalid blocksize (valid sizes: b >= %d && b <= %d)", minBlockSize, maxBlockSize)
)

// Pad pads the given data according to the PKCS #7 standard. This function uses
// 'append' to apply the padding. This means that it's possible that the
// underlying data of the original slice gets modified in the process.
func Pad(data []byte, blockSize int) ([]byte, error) {
	if err := checkBlockSize(blockSize); err != nil {
		return nil, err
	}

	diff := blockSize - len(data)%blockSize
	data = append(data, make([]byte, diff)...)
	dataLen := len(data)

	for i := 0; i < diff; i++ {
		data[dataLen-1-i] = byte(diff)
	}

	return data, nil
}

// Unpad unpads the given data according to the PKCS #7 standard. This function
// returns a new slice of the same underlying data as the input. It does not
// make a copy of the input.
func Unpad(data []byte, blockSize int) ([]byte, error) {
	if err := checkBlockSize(blockSize); err != nil {
		return nil, err
	}

	dataLen := len(data)
	if dataLen == 0 {
		return nil, ErrEmpty
	}

	if dataLen%blockSize != 0 {
		return nil, ErrFullBlocks
	}

	count := data[dataLen-1]
	if int(count) > blockSize {
		return nil, ErrPadding
	}

	if int(count) > dataLen {
		return nil, ErrPadding
	}

	pos := dataLen - int(count)
	padding := data[pos:]

	for _, b := range padding {
		if b != count {
			return nil, ErrPadding
		}
	}

	return data[:pos], nil
}

func checkBlockSize(blockSize int) (err error) {
	if blockSize < minBlockSize || blockSize > maxBlockSize {
		err = ErrBlockSize
	}
	return
}
