package saltboot

import (
	"log"
	"net/http"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[HealthCheckHandler] handleHealtchCheck executed")
	w.Header().Set("Content-Type", "application/json")
	model.Response{Status: "OK", Version: Version + "-" + BuildTime}.WriteHttp(w)
}
