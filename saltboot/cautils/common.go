package cautils

import (
	"encoding/pem"
	"io/ioutil"
)

type ToPem interface {
	ToPEM() ([]byte, error)
}

func newFromPEMFile(filename string, creator func([]byte) (interface{}, error)) (interface{}, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return creator(data)
}

func toPemImpl(pemType string, derBytes []byte) ([]byte, error) {
	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	return pemBytes, nil
}

func toPemFileImpl(source ToPem, filename string) error {
	pemBytes, err := source.ToPEM()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, pemBytes, 0400)
}
