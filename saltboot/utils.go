package saltboot


import (
  "errors"
  "net/http"
	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)


func RecoverWrap(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        var err error
        defer func() {
            r := recover()
            if r != nil {
                switch t := r.(type) {
                case string:
                    err = errors.New(t)
                case error:
                    err = t
                default:
                    err = errors.New("Unknown error")
                }
                model.Response{Status: err.Error()}.WriteInternalServerErrorHttp(w)
            }
        }()
        h.ServeHTTP(w, r)
    })
}
