package saltboot

import "testing"

func TestString(t *testing.T) {
	ar := SaltActionRequest{
		Server: "10.0.0.0",
		Action: "start",
	}

	expected := "{\"server\":\"10.0.0.0\",\"action\":\"start\"}"
	if ar.String() != expected {
		t.Errorf("SaltActionRequest.String() %s == %s", expected, ar.String())
	}
}
