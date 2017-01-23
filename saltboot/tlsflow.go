package saltboot
import (
	"github.com/hortonworks/salt-bootstrap/saltboot/cautils"
  "fmt"
  "log"
  "net/http"
  "os"
)


func PrivateKeyHandler(w http.ResponseWriter, req *http.Request) {
  // mkdir if needed
  log.Printf("[CAHandler] handlePrivateKey executed")
	w.Header().Set("Content-Type", "application/json")

  if cautils.IsPathExisting("./tlsauth") == false {
    if err := os.Mkdir("./tlsauth", 0755); err != nil {
      fmt.Fprintf(w, "FAIL")
      return
    }
  }
  if cautils.IsPathExisting("./tlsauth/client.key") == false {
    key, err := cautils.NewKey()
  	if err != nil {
       fmt.Fprintf(w, "FAIL")
  		 panic(err)
  	}


    err = key.ToPEMFile("./tlsauth/client.key")
  	if err != nil {
       fmt.Fprintf(w, "FAIL")
  		 panic(err)
  	}
  }
	fmt.Fprintf(w, "OK")
}

func CsrGenHandler(w http.ResponseWriter, req *http.Request) {
  log.Printf("[CAHandler] handleCsrGen executed")
	w.Header().Set("Content-Type", "application/json")
  if cautils.IsPathExisting("./tlsauth/client.key") == false {
    fmt.Fprintf(w, "FAIL")
    return
  }
  if cautils.IsPathExisting("./tlsauth/client.csr") == false {
    key, err  := cautils.NewKeyFromPrivateKeyPEMFile("./tlsauth/client.key")
    if err != nil {
       fmt.Fprintf(w, "FAIL")
  		 panic(err)
  	}

    csr, err := cautils.NewCertificateRequest(key)
    if err != nil {
       fmt.Fprintf(w, "FAIL")
       panic(err)
    }
    err = csr.ToPEMFile("./tlsauth/client.csr")
  	if err != nil {
       fmt.Fprintf(w, "FAIL")
  		 panic(err)
  	}
  }
  fmt.Fprintf(w, "OK")

}
