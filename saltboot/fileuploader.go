package saltboot

import (
    "log"
    "net/http"
    "fmt"
    "io/ioutil"
)

//http://play.golang.org/p/MrE9BwNbB1
func FileUploadHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[fileUploadHandler] execute file upload")

    file, header, err := req.FormFile("file")
    if err != nil {
        fmt.Fprintln(w, err)
        return
    }

    b, _ := ioutil.ReadAll(file)
    fmt.Printf(string(b))

    defer file.Close()
    fmt.Fprintf(w, "File %s uploaded successfully.", header.Filename)
}
