package model

import (
    "fmt"
    "strings"
    "encoding/json"
    "net/http"
    "log"
)

type Response struct {
    Status     string   `json:"status,omitempty"`
    ErrorText  string   `json:"errorText,omitempty"`
    Address    string   `json:"address,omitempty"`
    StatusCode int      `json:"statusCode,omitempty"`
}

type Responses struct {
    Responses []Response   `json:"responses"`
}

func (r *Response) Fill(outStr string, err error) {
    if err != nil {
        r.Status = "ERR"
        r.ErrorText = strings.TrimSpace(outStr + " " + err.Error())
    } else {
        r.Status = "OK"
    }
}

func (r Responses) String() string {
    j, _ := json.Marshal(r)
    return fmt.Sprintf("Responses: %s", string(j))
}

func (r Response) String() string {
    j, _ := json.Marshal(r)
    return fmt.Sprintf("Response: %s", string(j))
}

func (r Response) WriteHttp(w http.ResponseWriter) (resp Response) {
    w.WriteHeader(r.StatusCode)
    return EncodeJson(r, w)
}

func (r Response) WriteBadRequestHttp(w http.ResponseWriter) (resp Response) {
    w.WriteHeader(http.StatusBadRequest)
    return EncodeJson(r, w)
}

func EncodeJson(r Response, w http.ResponseWriter) (resp Response) {
    err := json.NewEncoder(w).Encode(r)
    if err != nil {
        log.Printf("[writehttp] failed to create json from model: %s", err.Error())
    }
    return r
}