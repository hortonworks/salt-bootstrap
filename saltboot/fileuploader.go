package saltboot

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

func FileUploadHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[fileUploadHandler] execute file upload")

	w.Header().Set("Content-Type", "text/plain")

	path := req.FormValue("path")
	log.Printf("[fileUploadHandler] path: " + path)

	file, header, err := req.FormFile("file")
	if err != nil {
		log.Printf("[fileUploadHandler] form file error: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("400 Bad Request"))
		fmt.Fprintln(w, err)
		return
	}

	b, _ := ioutil.ReadAll(file)

	err = os.MkdirAll(path, 0744)
	if err != nil {
		log.Printf("[fileUploadHandler] make dir error: " + err.Error())
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
		fmt.Fprintln(w, err)
		return
	}

	if strings.Contains(header.Filename, ".zip") {
		log.Printf("[fileUploadHandler] unzip file from /tmp")
		ioutil.WriteFile("/tmp/"+header.Filename, b, 0644)
		err = Unzip("/tmp/"+header.Filename, path)
		if err != nil {
			log.Printf("[fileUploadHandler] unzipt file error: " + err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			fmt.Fprintln(w, err)
			return
		}
	} else {
		log.Printf("[fileUploadHandler] FileName: " + header.Filename)
		err = ioutil.WriteFile(path+"/"+header.Filename, b, 0644)
		if err != nil {
			log.Printf("[fileUploadHandler] wirte file error: " + err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
			fmt.Fprintln(w, err)
			return
		}
	}

	defer file.Close()
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("201 Created"))
	fmt.Fprintf(w, "File %s uploaded successfully.", header.Filename)
}
