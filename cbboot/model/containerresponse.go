package model

import "fmt"

type ContainerResponse struct {
	Response
	Container Container `json:"container"`
}

func (r ContainerResponse) String() string {
	return fmt.Sprintf("ContainerResponse[Status: %s, ErrorText: %, Container: %]", r.Status, r.ErrorText, r.Container)
}
