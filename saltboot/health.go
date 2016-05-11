package saltboot

import (
    "log"
    "github.com/sequenceiq/salt-bootstrap/saltboot/model"
    "net/http"
)

func HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[HealthCheckHandler] handleHealtchCheck executed")
    w.Header().Set("Content-Type", "application/json")
    model.Response{Status: "OK", Version:Version + "-" + BuildTime}.WriteHttp(w)
}
