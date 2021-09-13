package checkproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

var ok []byte = []byte("Excellent!!")

func okResponse(w http.ResponseWriter, r *http.Request) {
	w.Write(ok)
}

func TestCheckIPInNetworkList(t *testing.T) {
	testCases := map[string]bool{
		"127.0.0.1": true,
		"0.0.0.0":   false,
		"10.0.0.1":  true,
		"not an ip": false,
	}
	networkList := []string{
		"10.0.0.1/24",
		"10.1.0.1",
		"127.0.0.1",
	}
	for ip, expectedValue := range testCases {
		if ans := CheckIPInNetworkList(ip, networkList); ans != expectedValue {
			t.Fatalf("Expected %v got %v for IP %v in list %v", expectedValue, ans, ip, networkList)
		}
	}

	brokenList := []string{"not an address", "10.0.0.0/100"}

	if ans := CheckIPInNetworkList("127.0.0.1", brokenList); ans == true {
		t.Fatalf("Expected broken list to give false, got true. IP: %v, List: %v", "127.0.0.1", brokenList)
	}
}

func TestCheckProxyDisabledWithForwarded(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	rec := httptest.NewRecorder()

	CheckProxy(false, []string{""})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatal("Response Code should be 400")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, []byte("Detected proxy: but application is not configured to use one")) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyDisabledWithoutForwarded(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	CheckProxy(false, []string{""})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatal("Response Code should be 200")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, ok) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyEnabledWithoutForwarded(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	CheckProxy(true, []string{""})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatal("Response Code should be 400")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, []byte("Expected a proxy: X-Forwarded-For empty")) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyEnabledWithForwardedTrustedProxy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	req.RemoteAddr = "10.0.0.1:10101"
	rec := httptest.NewRecorder()

	CheckProxy(true, []string{"10.0.0.1"})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatal("Response Code should be 200")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, ok) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyEnabledWithForwardedUntrustedProxy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	req.RemoteAddr = "10.0.0.1:10101"
	rec := httptest.NewRecorder()

	CheckProxy(true, []string{"10.0.0.2"})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatal("Response Code should be 400")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, []byte("Untrusted proxy")) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyEnabledWithForwardedUnexpectedRemoteAddrFormat(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	req.RemoteAddr = "asdasjd"
	rec := httptest.NewRecorder()

	CheckProxy(true, []string{"10.0.0.2"})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatal("Response Code should be 400")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, []byte("Untrusted proxy")) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}

func TestCheckProxyEnabledWithForwardedIPRemoteAddrFormat(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	req.RemoteAddr = "10.0.0.1"
	rec := httptest.NewRecorder()

	CheckProxy(true, []string{"10.0.0.2"})(http.HandlerFunc(okResponse)).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatal("Response Code should be 400")
	}
	body := rec.Body.Bytes()
	if bytes.Compare(body, []byte("Untrusted proxy")) != 0 {
		t.Fatalf("Unexpected output (got %v)", string(body))
	}
}
