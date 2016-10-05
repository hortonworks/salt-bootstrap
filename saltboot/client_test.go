package saltboot

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/hortonworks/salt-bootstrap/saltboot/model"
)

func TestDistributeAddressImpl(t *testing.T) {
	f := func(clients []string, payload []byte, endpoint string, user string, pass string) <-chan model.Response {
		c := make(chan model.Response, len(clients))
		for _, client := range clients {
			c <- model.Response{StatusCode: 200, ErrorText: "", Address: client}
		}
		close(c)
		return c
	}
	clients := []string{"a", "b", "c"}
	resp := distributeImpl(f, clients, make([]byte, 0), "/", "user", "pass")

	if len(resp) != len(clients) {
		t.Errorf("length not match %d == %d", len(clients), len(resp))
	}
}

func TestClientHostnameHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", bytes.NewBuffer(make([]byte, 0)))

	ClientHostnameHandler(w, r)

	if w.Code != 200 {
		t.Error("couldn't resolve hostname")
	}

	decoder := json.NewDecoder(w.Body)
	var resp map[string]interface{}
	decoder.Decode(&resp)

	if resp["statusCode"].(float64) != float64(200) {
		t.Error("status code not match 200 ==", resp["statusCode"].(float64))
	}
	if len(resp["status"].(string)) == 0 {
		t.Error("missing hostname")
	}
}
