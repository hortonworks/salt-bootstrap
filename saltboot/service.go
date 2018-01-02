package saltboot

import (
	"net/http"

	"log"
	"strings"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func RestartService(service string) (model.Response, error) {
	alreadyRunning, psOutput := IsServiceRunning(service)

	if alreadyRunning {
		log.Printf("[RestartService] %s is already running %s, restart", service, psOutput)
		return SetServiceState(service, RESTART_ACTION)
	} else {
		log.Printf("[RestartService] %s is not running (no need to stop first) and will be started", service)
		return LaunchService(service)
	}
}

func LaunchService(service string) (model.Response, error) {
	alreadyRunning, psOutput := IsServiceRunning(service)

	if alreadyRunning {
		log.Printf("[LaunchService] %s is already running %s", service, psOutput)
		return model.Response{StatusCode: http.StatusOK, Status: service + " is already running"}, nil
	} else {
		log.Printf("[LaunchService] %s is not running and will be started", service)
	}

	return SetServiceState(service, START_ACTION)
}

func StopService(service string) (model.Response, error) {
	return SetServiceState(service, STOP_ACTION)
}

func IsServiceRunning(service string) (bool, string) {
	log.Printf("[IsServiceRunning] check if service: %s is running", service)
	psOutput, _ := ExecCmd("ps", "aux")
	return strings.Contains(psOutput, service), psOutput
}

func SetServiceState(service string, serviceAction string) (resp model.Response, err error) {
	initSystem := GetInitSystem()
	action := initSystem.ActionCommand(service, serviceAction)
	result, err := ExecCmd(action[0], action[1:len(action)]...)
	if err != nil {
		return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
	}
	var state []string
	if serviceAction == STOP_ACTION {
		state = initSystem.StateCommand(service, false)
	} else {
		state = initSystem.StateCommand(service, true)
	}
	result, err = ExecCmd(state[0], state[1:len(state)]...)
	if err != nil {
		return model.Response{ErrorText: err.Error(), StatusCode: http.StatusInternalServerError}, err
	}
	resp = model.Response{Status: result, StatusCode: http.StatusOK}
	return resp, nil
}
