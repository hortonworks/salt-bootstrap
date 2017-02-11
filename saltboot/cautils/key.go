package cautils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Key struct {
	/*
	  PublicKey *crypto.PublicKey
	  PrivateKey *rsa.PrivateKey
	*/
	PublicKey  crypto.PublicKey
	PrivateKey *rsa.PrivateKey
	DerBytes   []byte
}

func keyFactoryByPEM(pemBytes []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("decode pem failed")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	newKey := Key{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		DerBytes:   pemBlock.Bytes,
	}

	return newKey, nil
}

func NewKey() (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	derBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if derBytes == nil {
		return nil, errors.New("marshal rsa failed")
	}

	newKey := &Key{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		DerBytes:   derBytes,
	}

	return newKey, nil
}

func NewKeyFromPrivateKeyPEM(pemBytes []byte) (*Key, error) {
	// currently we only support rsa
	rawKey, err := keyFactoryByPEM(pemBytes)
	key := rawKey.(Key)
	return &key, err
}

func NewKeyFromPrivateKeyPEMFile(filename string) (*Key, error) {
	rawKey, err := newFromPEMFile(filename, keyFactoryByPEM)
	key := rawKey.(Key)
	return &key, err
}

func (key *Key) ToPEM() ([]byte, error) {
	return toPemImpl("RSA PRIVATE KEY", key.DerBytes)
}

func (key *Key) ToPEMFile(filename string) error {
	return toPemFileImpl(key, filename)
}
