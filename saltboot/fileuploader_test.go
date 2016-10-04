package saltboot

import (
	"archive/zip"
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsNotMultipart(t *testing.T) {
	req := httptest.NewRequest("POST", "http://fileupload", nil)
	writer := httptest.NewRecorder()

	FileUploadHandler(writer, req)

	if writer.Code != 400 {
		t.Errorf("Wrong status code %d == %d", 400, writer.Code)
	}
}

func TestUpload(t *testing.T) {
	body := &bytes.Buffer{}
	multiWriter := multipart.NewWriter(body)
	part, _ := multiWriter.CreateFormFile("file", "test.txt")
	expected := []byte("content")
	part.Write(expected)
	multiWriter.Close()

	tempDirName, _ := ioutil.TempDir("", "fileuploadertest")
	defer os.RemoveAll(tempDirName)

	req := httptest.NewRequest("POST", "http://fileupload?path="+tempDirName, body)
	req.Header.Set("Content-Type", multiWriter.FormDataContentType())
	writer := httptest.NewRecorder()

	FileUploadHandler(writer, req)

	content, _ := ioutil.ReadFile(tempDirName + string(filepath.Separator) + "test.txt")

	if writer.Code != 201 {
		t.Errorf("Wrong status code %d == %d", 201, writer.Code)
	} else if len(expected) != len(content) {
		t.Errorf("Not match %s == %s", string(expected), string(content))
	}
}

func TestUploadZip(t *testing.T) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	defer zipWriter.Close()
	expected := []byte("content")
	zipEntry, _ := zipWriter.Create("test.txt")
	zipEntry.Write(expected)
	zipWriter.Close()

	tempDirName, _ := ioutil.TempDir("", "fileuploadertest")
	defer os.RemoveAll(tempDirName)

	zipFileName := filepath.Join(tempDirName, "test.zip")
	ioutil.WriteFile(zipFileName, buf.Bytes(), 0600)

	body := &bytes.Buffer{}
	multiWriter := multipart.NewWriter(body)
	defer multiWriter.Close()
	part, _ := multiWriter.CreateFormFile("file", "test.zip")
	file, _ := os.Open(zipFileName)
	defer file.Close()
	io.Copy(part, file)
	file.Close()
	multiWriter.Close()

	req := httptest.NewRequest("POST", "http://fileupload?path="+tempDirName, body)
	req.Header.Set("Content-Type", multiWriter.FormDataContentType())
	writer := httptest.NewRecorder()

	FileUploadHandler(writer, req)

	content, _ := ioutil.ReadFile(tempDirName + string(filepath.Separator) + "test.txt")

	if writer.Code != 201 {
		t.Errorf("Wrong status code %d == %d", 201, writer.Code)
	} else if len(expected) != len(content) {
		t.Errorf("Not match %s == %s", string(expected), string(content))
	}
}
