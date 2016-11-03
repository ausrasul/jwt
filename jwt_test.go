package jwt

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"time"
)

func TestConfigure(t *testing.T){
	err := Configure(
		map[string]interface{}{
			"privateKeyFile":         "tests/privkey.pem",
			"publicKeyFile":          "tests/pubkey.pem",
			"algorithm":              "RS256",
			"sessionName":            "My_application_name_no_spaces",
			"sessionTimeout":         5, // seconds
			"sessionRefreshInterval": 2, //seconds
		},
	)
	if err != nil{
		t.Error("Expected err nil, got err ", err)
	}
	if std.conf.algorithm != "RS256" {
		t.Error("Expected algorithm = RS256, got ", std.conf.algorithm )
	}
	if std.conf.sessionName != "My_application_name_no_spaces" {
		t.Error("Expected sessionName = My_application_name_no_spaces, got ", std.conf.sessionName )
	}
	if std.conf.sessionTimeout != 5 {
		t.Error("Expected sessionTimeout = 5, got ", std.conf.sessionTimeout )
	}
	if std.conf.sessionRefreshInterval != 2 {
		t.Error("Expected sessionRefreshInterval = 2, got ", std.conf.sessionRefreshInterval )
	}
}

func TestCreateParseToken(t *testing.T) {
	user := make(map[string]interface{})
	user["testValue"] = "test"
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "", nil)

	tokenString, err := CreateToken(user, w, r)
	tokenString = tokenString
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	user2, err := ParseToken(w, r)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}

	if user["testValue"] != user2["testValue"]{
		t.Error("Expected user exp \"test\" got ", user2["testValue"])
	}

}

func testTokenNoRefresh(t *testing.T) {
	user := make(map[string]interface{})
	user["testValue"] = "test"
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "", nil)

	_, err := CreateToken(user, w, r)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	time.Sleep(1 * time.Second)
	user2, err := ParseToken(w, r)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	if user["testValue"] != user2["testValue"]{
		t.Error("Expected user value \"test\" got ", user2["testValue"])
	}
	if user["exp"] != user2["exp"]{
		t.Error("Expected user exp ", user["exp"], " got ", user2["exp"])
	}

}

func TestTokenRefresh(t *testing.T) {
	user := make(map[string]interface{})
	user["testValue"] = "test"
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "", nil)

	tokenString, err := CreateToken(user, w, r)
	tokenString = tokenString
	//t.Error("token string ", tokenString)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	time.Sleep(3 * time.Second)
	user2, err := ParseToken(w, r)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	if user["testValue"] != user2["testValue"]{
		t.Error("Expected user value \"test\" got ", user2["testValue"])
	}
	if user["exp"] == user2["exp"]{
		t.Error("Expected user exp ", user["exp"], " got ", user2["exp"])
	}

}


func TestTokenTimeout(t *testing.T) {
	user := make(map[string]interface{})
	user["testValue"] = "test"
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "", nil)

	tokenString, err := CreateToken(user, w, r)
	tokenString = tokenString
	//t.Error("token string ", tokenString)
	if err != nil {
		t.Error("Expected err nil, got ", err)
	}
	time.Sleep(6 * time.Second)
	_, err = ParseToken(w, r)
	if err == nil {
		t.Error("Expected err timeout, got nil")
	}

}
