package cautils

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type Certificate struct {
	DerBytes []byte

	Crt *x509.Certificate
}

func CreateCertificate(template *x509.Certificate, baseCertificate *x509.Certificate, publicKey, privateKey interface{}) (*Certificate, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, baseCertificate, publicKey, privateKey)

	if err != nil {
		return nil, err
	}
	certificate, err := NewCertificateFromDER(derBytes)
	return certificate, err
}

func NewCaCertificate(key *Key) (*Certificate, error) {

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 365 * 24)
	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               GenSubject("Hortonworks", ""),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}
	template.IsCA = true
	return CreateCertificate(template, template, key.PublicKey, key.PrivateKey)
}

func GenSubject(organization string, domains string) pkix.Name {
	return pkix.Name{
		Organization:       []string{organization},
		CommonName:         domains,
		OrganizationalUnit: []string{"Cloudbreak"},
		Country:            []string{"US"},
		Province:           []string{"CA"},
	}
}

func certificateFactoryByDER(derBytes []byte) (Certificate, error) {
	crt, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return Certificate{}, err
	}

	cert := Certificate{
		DerBytes: derBytes,
		Crt:      crt,
	}

	return cert, nil
}

func certificateFactoryByPEM(pemBytes []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}

	cert, err := certificateFactoryByDER(pemBlock.Bytes)
	return cert, err
}

func NewCertificateFromDER(derBytes []byte) (*Certificate, error) {
	cert, err := certificateFactoryByDER(derBytes)
	return &cert, err
}

func NewCertificateFromPEM(pemBytes []byte) (*Certificate, error) {
	rawCert, err := certificateFactoryByPEM(pemBytes)
	cert := rawCert.(Certificate)
	return &cert, err
}

func NewCertificateFromPEMFile(filename string) (*Certificate, error) {
	rawCert, err := newFromPEMFile(filename, certificateFactoryByPEM)
	cert := rawCert.(Certificate)
	return &cert, err
}

func (certificate *Certificate) ToPEM() ([]byte, error) {
	return toPemImpl("CERTIFICATE", certificate.DerBytes)
}

func (certificate *Certificate) ToPEMFile(filename string) error {
	return toPemFileImpl(certificate, filename)
}
func (certificate *Certificate) GetSerialNumber() *big.Int {
	return certificate.Crt.SerialNumber
}
