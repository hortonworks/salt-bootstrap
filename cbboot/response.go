package cbboot

import "fmt"

type Response struct {
	Status    string   `json:"status"`
	ErrorText    string   `json:"errorText"`
	Container Container `json:"container"`
}

func (r Response) String() string {
	return fmt.Sprintf("Response[Status: %s, ErrorText: %, Container: %]", r.Status, r.ErrorText, r.Container)
}
