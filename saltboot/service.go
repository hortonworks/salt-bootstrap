package saltboot

import (
    "github.com/sequenceiq/salt-bootstrap/saltboot/model"
    "net/http"
)

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
