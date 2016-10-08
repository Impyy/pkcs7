# pkcs7

Package pkcs7 implements data padding as specified by the PKCS #7 standard. See
also: https://tools.ietf.org/html/rfc5652#section-6.3.

The code is licensed under the [MIT license](LICENSE).

## Usage

```go
package main

import (
	"fmt"

	"github.com/Impyy/pkcs7"
)

func main() {
	const blockSize = 6
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	padded, err := pkcs7.Pad(data, blockSize)
	if err != nil {
		panic(err)
	}

	unpadded, err := pkcs7.Unpad(padded, blockSize)
	if err != nil {
		panic(err)
	}

	fmt.Printf("before: %X\n", data)
	fmt.Printf("padded: %X\n", padded)
	fmt.Printf("unpadded: %X\n", unpadded)
}
```

```none
before: DEADBEEF
padded: DEADBEEF0202
unpadded: DEADBEEF
```