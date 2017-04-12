package cautils

import (
	"encoding/pem"
	"io/ioutil"
	"log"
)

const (
	caLocKey      = "SALTBOOT_CA"
	defaultCaLoc  = "./ca"
	crtLocKey     = "SALTBOOT_CRT"
	defaultCrtLoc = "./crt"
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

func DetermineCaRootDir(getEnv func(key string) string) string {
	caLocation := getFromEnvOrDefault(getEnv, caLocKey, defaultCaLoc)
	log.Printf("[determineCaRootDir] CA_ROOT_DIR: %s", caLocation)
	return caLocation
}

func DetermineCrtDir(getEnv func(key string) string) string {
	crtLocation := getFromEnvOrDefault(getEnv, crtLocKey, defaultCrtLoc)
	log.Printf("[determineCaRootDir] CRT_TARGET_DIR: %s", crtLocation)
	return crtLocation
}

func getFromEnvOrDefault(getEnv func(key string) string, key string, defaultValue string) string {
	envValue := getEnv(key)
	if len(envValue) == 0 {
		return defaultValue
	}
	return envValue

}
