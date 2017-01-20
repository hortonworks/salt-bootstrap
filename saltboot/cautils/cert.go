package cautils

import (

  "math/big"
  "errors"
  "crypto/x509"
  "crypto/x509/pkix"
  "io/ioutil"
  "encoding/pem"
  "time"
  "crypto/rand"
)

type Certificate struct {

  DerBytes []byte

  Crt *x509.Certificate

}

func CreateCertificate(template *x509.Certificate, baseCertificate *x509.Certificate, publicKey, privateKey interface{}) (*Certificate, error){
  derBytes, err := x509.CreateCertificate(rand.Reader, template, baseCertificate, publicKey, privateKey)

  if err != nil {
    return nil, err
  }
  certificate, err := NewCertificateFromDER(derBytes)
  return certificate, err
}

func NewCaCertificate(key *Key) (*Certificate, error) {

  notBefore := time.Now()
  notAfter  := notBefore.Add(time.Hour*365*24)
  keyUsage  := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |  x509.KeyUsageCertSign
  extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
  template := &x509.Certificate{
    SerialNumber: big.NewInt(1),
    Subject: GenSubject("Hortonworks"),
    NotBefore: notBefore,
    NotAfter: notAfter,
    KeyUsage: keyUsage,
    ExtKeyUsage: extKeyUsage,
    BasicConstraintsValid: true,
  }
  template.IsCA = true
  return CreateCertificate(template, template, key.PublicKey, key.PrivateKey)
}

func GenSubject(organization string) pkix.Name {
  return pkix.Name {
    Organization: []string{organization},
  }
}
func NewCertificateFromDER(derBytes []byte) (*Certificate, error) {

  crt, err := x509.ParseCertificate(derBytes)
  if err != nil {
    return nil, err
  }

  cert := &Certificate{
    DerBytes: derBytes,
    Crt: crt,
  }

  return cert, nil
}
func NewCertificateFromPEM(pemBytes []byte) (*Certificate, error) {

  pemBlock, _ := pem.Decode(pemBytes)
  if pemBlock == nil {
    return nil, errors.New("PEM decode failed")
  }

  crt, err := x509.ParseCertificate(pemBlock.Bytes)
  if err != nil {
    return nil, err
  }

  cert := &Certificate{
    DerBytes: pemBlock.Bytes,
    Crt: crt,
  }

  return cert, nil
}
func NewCertificateFromPEMFile(filename string) (*Certificate, error) {

  data, err := ioutil.ReadFile(filename)
  if err != nil {
    return nil, err
  }

  return NewCertificateFromPEM(data)
}

func (certificate *Certificate) ToPEM() ([]byte, error) {

  pemBlock := &pem.Block{
    Type: "CERTIFICATE",
    Bytes: certificate.DerBytes,
  }

  pemBytes := pem.EncodeToMemory(pemBlock)

  return pemBytes, nil
}
func (certificate *Certificate) ToPEMFile(filename string) (error) {
  pemBytes, err := certificate.ToPEM()
  if err != nil {
    return err
  }

  return ioutil.WriteFile(filename, pemBytes, 0400)
}
func (certificate *Certificate) GetSerialNumber() *big.Int {
  return certificate.Crt.SerialNumber
}
