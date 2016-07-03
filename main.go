package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var oauthconf *oauth2.Config
var cookiestore = sessions.NewCookieStore([]byte("something-very-secret-minoris-and-other-things-that-should-not-be-gitted :)"))

type Config struct {
	ClientID     string
	ClientSecret string
}

type ClaimSet struct {
	Sub string
}

type Token struct {
	ID   string
	Time time.Time
	User string
}

func login(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	url := oauthconf.AuthCodeURL("state")
	log.Print(url)
	fmt.Fprintf(w, "You want to login token<br/>\n")
	fmt.Fprintf(w, "<a href='%s'>Login google</a><br/>", url)
}

// decodeIdToken takes an ID Token and decodes it to fetch the Google+ ID within
func decodeIdToken(idToken string) (gplusID string, err error) {
	// An ID token is a cryptographically-signed JSON object encoded in base 64.
	// Normally, it is critical that you validate an ID token before you use it,
	// but since you are communicating directly with Google over an
	// intermediary-free HTTPS channel and using your Client Secret to
	// authenticate yourself to Google, you can be confident that the token you
	// receive really comes from Google and is valid. If your server passes the ID
	// token to other components of your app, it is extremely important that the
	// other components validate the token before using it.
	var set ClaimSet
	if idToken != "" {
		// Check that the padding is correct for a base64decode
		parts := strings.Split(idToken, ".")
		if len(parts) < 2 {
			return "", fmt.Errorf("Malformed ID token")
		}
		// Decode the ID token
		b, err := base64Decode(parts[1])
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
		err = json.Unmarshal(b, &set)
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
	}
	return set.Sub, nil
}

func base64Decode(s string) ([]byte, error) {
	// add back missing padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func token(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Sorry", 500)
		log.Fatal(err)
		return
	}

	tok, err := oauthconf.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		log.Print(err)
	}
	id_tok := tok.Extra("id_token").(string)

	gplusID, err := decodeIdToken(id_tok)
	session.Values["userid"] = gplusID
	session.Save(r, w)

	log.Printf("Gplusid: %s\n", gplusID)

	http.Redirect(w, r, "/info", 303)
}

func init_rand() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var tokens []*Token

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}

func genereateToken() *Token {
	var token *Token
	token = nil

	// Find free token
	for i, t := range tokens {
		if t == nil || t.Time.Before(time.Now()) {
			tokens[i] = new(Token)
			token = tokens[i]
			break
		}
	}

	if token == nil {
		log.Panic("Can't find free token")
	}

	token.ID = RandStringRunes(30)
	token.User = "unknown"
	token.Time = time.Now().Add(time.Second * 120)

	return token
}

func findToken() *Token {
	return nil
}

func failOnErr(err error, w http.ResponseWriter, r *http.Request) {
	if err != nil {
		http.Error(w, "Sorry", 500)
		log.Fatal(err)
		return
	}
}

func getToken(w http.ResponseWriter, r *http.Request) {
	session := menu(w, r)

	if session.Values["userid"] == nil {
		http.Redirect(w, r, "/login", 303)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := genereateToken()
	t.User = session.Values["userid"].(string)

	fmt.Fprintf(w, "<a href='/getTokenInfo?token=%s'>Info</a>", t.ID)
}

func getTokenInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tokenId := r.FormValue("token")

	for _, t := range tokens {
		if t != nil && t.Time.After(time.Now()) && tokenId == t.ID {
			fmt.Fprintf(w, "<pre>%+v</pre><br/>", t)
			break
		}
	}
}

func (token *Token) Valid() bool {
	return token != nil && token.Time.After(time.Now())
}

func menu(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, err := cookiestore.Get(r, "session-name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	failOnErr(err, w, r)

	fmt.Fprintf(w, "<a href='/info'>Info</a> ")
	fmt.Fprintf(w, "<a href='/gettoken'>GetToken</a> ")
	fmt.Fprintf(w, "<br/>")

	return session

}

func info(w http.ResponseWriter, r *http.Request) {
	session := menu(w, r)

	fmt.Fprintf(w, "Userid: %s<br/>\n", session.Values["userid"].(string))

	for _, t := range tokens {
		if t.Valid() && t.User == session.Values["userid"].(string) {
			fmt.Fprintf(w, "<li>%v</li>", t)
		}
	}

}

func main() {
	init_rand()
	tokens = make([]*Token, 50)

	var config Config
	if _, err := toml.DecodeFile("/opt/oauthauth/config.toml", &config); err != nil {
		log.Fatal(err)
	}

	oauthconf = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  "http://auth.kent.wr25.org/token",
		Scopes: []string{
			"https://www.googleapis.com/auth/plus.login",
		},
		Endpoint: google.Endpoint,
	}

	r := mux.NewRouter()

	http.Handle("/", r)

	r.HandleFunc("/login", login)
	r.HandleFunc("/token", token)
	r.HandleFunc("/gettoken", getToken)
	r.HandleFunc("/getTokenInfo", getTokenInfo)
	r.HandleFunc("/info", info)

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		log.Fatal(err)
	}
}
