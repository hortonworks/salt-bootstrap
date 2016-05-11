package saltboot

import (
    "net/http"
    "log"
    "strings"
    "encoding/base64"
)

type Authenticator struct {
    Username string
    Password string
}

func (a *Authenticator) Wrap(handler func(w http.ResponseWriter, req *http.Request)) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        valid := CheckAuth(a.Username, a.Password, r)
        if !valid {
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte("401 Unauthorized"))
            return
        }
        w.Header().Set("Content-Type", "application/json")
        http.HandlerFunc(handler).ServeHTTP(w, r)
    })
}

func CheckAuth(user string, pass string, r *http.Request) bool {
    hUser, hPassword := GetAuthUserPass(r)
    result := user == hUser && pass == hPassword
    if !result {
        log.Printf("[auth] invalid autorization header: %s from %s", r.Header.Get("Authorization"), r.Host)
    }
    return result
}

func GetAuthUserPass(r *http.Request) (string, string) {
    s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
    if len(s) != 2 || s[0] != "Basic" {
        log.Printf("[auth] Missing Basic authorization header")
        return "", ""
    }
    b, err := base64.StdEncoding.DecodeString(s[1])
    if err != nil {
        log.Printf("[auth] Authorization header is not MD5 encoded: %s", err.Error())
        return "", ""
    }
    pair := strings.Split(string(b), ":")
    if len(pair) != 2 {
        log.Printf("[auth] Missing username/password")
        return "", ""
    }
    return pair[0], pair[1]
}