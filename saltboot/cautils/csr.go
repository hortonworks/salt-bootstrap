package cautils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"time"
	"net"
)

type CertificateRequest struct {
	DerBytes []byte

	Csr *x509.CertificateRequest
}

func NewCertificateRequest(key *Key) (*CertificateRequest, error) {
	ip, _, _ := net.ParseCIDR("127.0.0.1/24")
	i2, _, _ := net.ParseCIDR("10.0.108.154/32")

	template := &x509.CertificateRequest{
		//Attributes:
		//SignatureAlgorithm,
		//Extensions:
    Subject: GenSubject("Hortonworks", "server.dc1.consul"),
		DNSNames: []string{"localhost", "server.dc1.consul"},
		//EmailAddress:
		IPAddresses: []net.IP{ip, i2},
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	csr, err := NewCertificateRequestFromDER(derBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func SignCsr(ca *CA, csr *CertificateRequest) (*Certificate, error) {
	serialNumber, err := ca.GetSerialNumber()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 365 * 24)
	keyUsage := x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              csr.Csr.DNSNames,
                IPAddresses:           csr.Csr.IPAddresses,
	}
	return CreateCertificate(template, ca.Certificate.Crt, csr.Csr.PublicKey, ca.Key.PrivateKey)
}

func NewCertificateRequestFromDER(derBytes []byte) (*CertificateRequest, error) {

	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}

	certificateRequest := &CertificateRequest{
		DerBytes: derBytes,
		Csr:      csr,
	}

	return certificateRequest, nil
}
func NewCertificateRequestFromPEM(pemBytes []byte) (*CertificateRequest, error) {

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}

	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	certificateRequest := &CertificateRequest{
		DerBytes: pemBlock.Bytes,
		Csr:      csr,
	}

	return certificateRequest, nil
}
func NewCertificateRequestFromPEMFile(filename string) (*CertificateRequest, error) {

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return NewCertificateRequestFromPEM(data)
}

func (csr *CertificateRequest) ToPEM() ([]byte, error) {

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.DerBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)

	return pemBytes, nil
}

func (csr *CertificateRequest) ToPEMFile(filename string) error {
	pemBytes, err := csr.ToPEM()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, pemBytes, 0400)
}
