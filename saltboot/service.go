package saltboot

import (
	"net/http"
	"os"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func LaunchService(service string) (resp model.Response, err error) {
	return SetServiceState(service, true)
}

func StopService(service string) (resp model.Response, err error) {
	return SetServiceState(service, false)
}

func SetServiceState(service string, up bool) (resp model.Response, err error) {
	initSystem := GetInitSystem(os.Stat)
	action := initSystem.ActionCommand(service, up)
	result, err := ExecCmd(action[0], action[1:len(action)]...)
	if err != nil {
		return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
	}
	state := initSystem.StateCommand(service, up)
	result, err = ExecCmd(state[0], state[1:len(state)]...)
	if err != nil {
		return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
	}
	resp = model.Response{Status: result, StatusCode: http.StatusOK}
	return resp, nil
}
