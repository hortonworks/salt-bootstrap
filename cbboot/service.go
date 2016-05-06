package cbboot

import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "encoding/json"
)

func StartSystemdService(w http.ResponseWriter, req *http.Request, service string) (out string, err error) {
    return StartSrv(w, req, service, true)
}

func StartService(w http.ResponseWriter, req *http.Request, service string) (out string, err error) {
    return StartSrv(w, req, service, false)
}

func LaunchService(service string) (resp model.Response, err error) {
    return SetServiceState(service, "start", "enable")
}

func StopService(service string) (resp model.Response, err error) {
    return SetServiceState(service, "stop", "disable")
}

func SetServiceState(service string, action string, state string) (resp model.Response, err error) {
    result, err := ExecCmd("/bin/systemctl", action, service)
    if err != nil {
        return model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}, err
    }
    result, err = ExecCmd("/bin/systemctl", state, service)
    if err != nil {
        return model.Response{ErrorText: err.Error(), StatusCode:http.StatusInternalServerError}, err
    }
    resp = model.Response{Status:result, StatusCode:http.StatusOK}
    return resp, nil
}

func StartSrv(w http.ResponseWriter, req *http.Request, service string, systemd bool) (out string, err error) {
    var result string
    if systemd {
        result, err = ExecCmd("/bin/systemctl", "start", service)
    } else {
        result, err = ExecCmd("/sbin/service", service, "start")
    }
    if err != nil {
        log.Printf("[startService] failed to start %s: %s", service, err.Error())
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(model.Response{ErrorText: err.Error(), StatusCode:500})
    } else {
        status := http.StatusOK
        cResp := model.Response{Status:result, StatusCode:status}
        log.Printf("[startService] %s service started: %s", service, result)
        json.NewEncoder(w).Encode(cResp)
    }
    return result, err
}

