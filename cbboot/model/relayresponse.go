package model

import "fmt"



type RelayResponse struct {
	Response
	Responses   []Response   `json:"responses"`

}

func (r RelayResponse) String() string {
	return fmt.Sprintf("Response[Status: %s, Address: %s]", r.Status, r.Address)
}

