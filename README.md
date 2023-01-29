# testcerts

![Actions Status](https://github.com/madflojo/testcerts/actions/workflows/go.yaml/badge.svg?branch=main)
 [![Coverage Status](https://coveralls.io/repos/github/madflojo/testcerts/badge.svg?branch=master)](https://coveralls.io/github/madflojo/testcerts?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/madflojo/testcerts)](https://goreportcard.com/report/github.com/madflojo/testcerts) [![Documentation](https://godoc.org/github.com/madflojo/testcerts?status.svg)](http://godoc.org/github.com/madflojo/testcerts)
[![license](https://img.shields.io/github/license/madflojo/testcerts.svg?maxAge=2592000)](https://github.com/madflojo/testcerts/LICENSE)

testcerts is a Go package that makes it easy for developers to generate x509 certificates for testing and development purposes. The package provides an easy-to-use API for generating self-signed certificates and keys, and saving them to both temporary and non-temporary files.

What makes testcerts unique is its ability to generate certificates and keys with a single line of code, and also its ability to handle saving them to temp and non-temp files, which eliminates the need for developers to handle file operations while testing their code.

Overall, testcerts simplifies the process of generating and managing test certificates, making it a valuable tool for any developer working with x509 certificates.

## Usage

### Generating Certificates to File

The `GenerateCertsToFile` function generates an X.509 certificate and key and writes them to the file paths provided.

```go
package main

import (
	"fmt"
	"github.com/<username>/testcerts"
)

func main() {
	certFile, keyFile, err := testcerts.GenerateCertsToFile("/tmp/cert.pem", "/tmp/key.pem")
	if err != nil {
		fmt.Printf("Error generating certificates: %s", err)
	}
	fmt.Printf("Certificate written to: %s\n", certFile)
	fmt.Printf("Key written to: %s\n", keyFile)
}
```

### Generating Certificates to Temporary File

The `GenerateCertsToTempFile` function generates an X.509 certificate and key and writes them to randomly generated files in the directory provided or the system's temporary directory if none is provided. The function returns the file paths of the generated files.

```go
package main

import (
	"fmt"
	"github.com/<username>/testcerts"
)

func main() {
	certFile, keyFile, err := testcerts.GenerateCertsToTempFile("/tmp/")
	if err != nil {
		fmt.Printf("Error generating certificates: %s", err)
	}
	fmt.Printf("Certificate written to: %s\n", certFile)
	fmt.Printf("Key written to: %s\n", keyFile)
}
```

### Generating Certificates

The `GenerateCerts` function generates an X.509 certificate and key and returns them as byte slices.

```go
package main

import (
	"fmt"
	"github.com/<username>/testcerts"
)

func main() {
	cert, key, err := testcerts.GenerateCerts()
	if err != nil {
		fmt.Printf("Error generating certificates: %s", err)
	}
	fmt.Printf("Certificate: %s\n", cert)
	fmt.Printf("Key: %s\n", key)
}
```

## Contributing

If you find a bug or have an idea for a feature, please open an issue or a pull request.

## License

testcerts is released under the MIT License. See [LICENSE](./LICENSE) for details.



