package cautils

import (
  "math/big"
  "os"
  "strconv"
  "strings"
  "io/ioutil"
)


type CA struct {
  RootDir string
  Certificate *Certificate
  Key *Key
}

func IsPathExisting(path string) bool {
  if _, err := os.Stat(path); os.IsNotExist(err) {
    return false
  }
  return true
}

func NewCA(rootDir string) (*CA, error) {

  // mkdir if needed
  if IsPathExisting(rootDir + "/ca") == false {
    if err := os.Mkdir(rootDir + "/ca", 0755); err != nil {
      return nil, err
    }
  }

  var key *Key
  var certificate *Certificate
  var err error
  if IsPathExisting(rootDir + "/ca/ca.key") == false {
    // gen priv key
    key, err = NewKey()
    if err != nil {
      return nil, err
    }
    if err := key.ToPEMFile(rootDir + "/ca/ca.key"); err != nil {
      return nil, err
    }


    certificate, err = NewCaCertificate(key)
    if err != nil {
      return nil, err
    }
    if err := certificate.ToPEMFile(rootDir + "/ca/ca.crt"); err != nil {
      return nil, err
    }

  } else {
    certificate, err = NewCertificateFromPEMFile(rootDir + "/ca/ca.crt")
    if err != nil {
      return nil, err
    }
    key, err = NewKeyFromPrivateKeyPEMFile(rootDir + "/ca/ca.key")
    if err != nil {
      return nil, err
    }

  }
  if IsPathExisting(rootDir + "/ca/ca.srl") == false {
  ioutil.WriteFile(rootDir + "/ca/ca.srl", []byte("2"), 0644)
}

  newCA := &CA{
    RootDir: rootDir,
    Certificate: certificate,
    Key: key,
  }

  return newCA, nil
}

func (ca *CA) GetSerialNumber() (*big.Int, error) {
  snStr, err := ioutil.ReadFile(ca.RootDir + "/ca/ca.srl")
  if err != nil {
    panic(err)
  }
  snInt, err := strconv.Atoi(strings.Trim(string(snStr), "\n"))
  if err != nil {
    panic(err)
  }
  sn := big.NewInt(int64(snInt))

  return sn, nil
}
func (ca *CA) IncreaseSerialNumber() error {
  snStr, err := ioutil.ReadFile(ca.RootDir + "/ca/ca.srl")
  if err != nil {
    panic(err)
  }
  snInt, err := strconv.Atoi(strings.Trim(string(snStr), "\n"))
  if err != nil {
    panic(err)
  }
  nextSnInt := snInt + 1
  nextSnStr := strconv.Itoa(nextSnInt) + "\n"
  ioutil.WriteFile(ca.RootDir + "/ca/ca.srl", []byte(nextSnStr), 0600)

  return nil
}
func (ca *CA) IssueCertificate(csr *CertificateRequest) (*Certificate, error) {
  cert, err := SignCsr(ca, csr)
  // increase sn
  if err = ca.IncreaseSerialNumber(); err != nil {
    return nil, err
  }

  return cert, nil
}
