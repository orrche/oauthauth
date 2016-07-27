package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var oauthconf *oauth2.Config
var cookiestore *sessions.CookieStore

type Config struct {
	ClientID     string
	ClientSecret string
}

type State struct {
	Users             []*User
	CookieStoreSecret string
}

type ClaimSet struct {
	Sub string
}

type Token struct {
	ID   string
	Time time.Time
	User string
}

type InviteToken struct {
	ID     string
	Time   time.Time
	User   string
	Groups []string
}

type User struct {
	ID       string
	GplusIDs []string
	Tokens   []Token
	Groups   []string
}

func (state *State) login(w http.ResponseWriter, r *http.Request) {
	menu(w, r, state)

	url := oauthconf.AuthCodeURL("state")
	log.Print(url)
	fmt.Fprintf(w, "Login in using google<br/>\n")
	fmt.Fprintf(w, "<a href='%s'>Google</a><br/>", url)
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

func (state *State) GetUserFromGplusID(gpid string) *User {
	for _, user := range state.Users {
		for _, id := range user.GplusIDs {
			if id == gpid {
				return user
			}
		}
	}

	return nil
}

func (state *State) token(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	if err != nil {
		session, err = cookiestore.New(r, "session-name")
		log.Print(err)
	}

	tok, err := oauthconf.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		log.Print(err)
	}
	id_tok := tok.Extra("id_token").(string)

	gplusID, err := decodeIdToken(id_tok)

	user := GetUserFromSession(state, session)
	if user != nil {
		user.GplusIDs = append(user.GplusIDs, gplusID)
		saveState(*state)
	} else {
		user := state.GetUserFromGplusID(gplusID)
		if user != nil {
			session.Values["userid"] = user.ID
			session.Save(r, w)
			log.Printf("Id: %s\n", user.ID)
		} else {
			log.Printf("Unknown user: %s\n", gplusID)
		}
	}

	http.Redirect(w, r, "/info", 303)
}

func init_rand() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var tokens []*Token
var inviteTokens []*InviteToken

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
		log.Panic(err)
	}
}

func (state *State) getToken(w http.ResponseWriter, r *http.Request) {
	session := menu(w, r, state)

	user := GetUserFromSession(state, session)

	if user == nil {
		http.Redirect(w, r, "/login", 303)
		return
	}

	t := genereateToken()
	t.User = user.ID

	fmt.Fprintf(w, "<a href='/gettokeninfo?token=%s'>Info</a>", t.ID)
}

func getTokenInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	tokenId := r.FormValue("token")

	for _, t := range tokens {
		if t.Valid() && tokenId == t.ID {
			enc := toml.NewEncoder(w)
			enc.Encode(t)
			return
		}
	}
}

func (token *InviteToken) Valid() bool {
	return token != nil && token.Time.After(time.Now())
}

func (token *Token) Valid() bool {
	return token != nil && token.Time.After(time.Now())
}

func menu(w http.ResponseWriter, r *http.Request, state *State) *sessions.Session {
	session, err := cookiestore.Get(r, "session-name")
	user := GetUserFromSession(state, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprintf(w, "<a href='/login'>Login</a> ")
	fmt.Fprintf(w, "<a href='/info'>Info</a> ")
	fmt.Fprintf(w, "<a href='/gettoken'>GetToken</a> ")
	if user.IsMemberOf("admin") {
		fmt.Fprintf(w, "<a href='/listinvites'>ListInvites</a> ")
	}
	fmt.Fprintf(w, "<a href='/createinvite'>CreateInvite</a> ")
	fmt.Fprintf(w, "<br/>")

	if err != nil {
		return nil
	}

	return session

}

/*
func GetUser(state *State, id string) *User {
	for _, user := range state.Users {
		if user.ID == id {
			return user
		}
	}

	return nil
}
*/

func GetUserFromSession(state *State, session *sessions.Session) *User {
	if session.Values["userid"] != nil {
		for _, user := range state.Users {
			if user.ID == session.Values["userid"].(string) {
				return user
			}
		}
	}
	return nil
}

func (state *State) info(w http.ResponseWriter, r *http.Request) {
	session := menu(w, r, state)
	user := GetUserFromSession(state, session)

	if user != nil {
		fmt.Fprintf(w, "Userid: %s<br/>\n", user.ID)
		for _, group := range user.Groups {
			fmt.Fprintf(w, "<li>%s</li>", group)
		}
	}

	for _, t := range tokens {
		if t.Valid() && t.User == session.Values["userid"].(string) {
			fmt.Fprintf(w, "<li>%v</li>", t)
		}
	}
}

func (state *State) GetUserFromId(id string) *User {
	for _, usr := range state.Users {
		if usr.ID == id {
			return usr
		}
	}
	return nil
}

func (state *State) getGroups(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	failOnErr(err, w, r)

	user := GetUserFromSession(state, session)

	if r.FormValue("user") == user.ID {
		data, err := json.Marshal(user.Groups)
		if err != nil {
			w.Write(data)
		}
	} else if !user.IsMemberOf("admin") {
		data, err := json.Marshal(state.GetUserFromId(r.FormValue("user")).Groups)
		if err != nil {
			w.Write(data)
		}
	}
}

func (state *State) createInvite(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	failOnErr(err, w, r)
	user := GetUserFromSession(state, session)

	if !user.IsMemberOf("admin") {
		return
	}

	if r.Method == "POST" {
		token := new(InviteToken)
		token.User = r.FormValue("name")
		for k, v := range r.PostForm {
			fmt.Fprintf(w, "K %s V %s\n", k, v)
		}
		token.Groups = make([]string, 1, 1)
		token.Groups[0] = r.FormValue("name")

		token.ID = RandStringRunes(30)
		token.Time = time.Now().Add(time.Second * 120)

		inviteTokens = append(inviteTokens, token)

		fmt.Fprintf(w, "Visite http://auth.kent.wr25.org/invite?token=%s to get a user", token.ID)
	} else {
		menu(w, r, state)
		fmt.Fprintf(w, "<form method='post'>")
		fmt.Fprintf(w, "Friendly Name: <input type='text' name='name'/><br/>")
		for _, group := range []string{"admin"} {
			fmt.Fprintf(w, "<input type='checkbox' value='%s'></input> %s<br/>", group, group)
		}
		fmt.Fprintf(w, "<input type='submit'/><br/>")
		fmt.Fprintf(w, "</form>")
	}
}

func (user User) IsMemberOf(group string) bool {
	for _, g := range user.Groups {
		if g == group {
			return true
		}
	}

	return false
}

func (state *State) listPendingInvites(w http.ResponseWriter, r *http.Request) {
	session := menu(w, r, state)
	user := GetUserFromSession(state, session)

	if !user.IsMemberOf("admin") {
		fmt.Fprintf(w, "Access denied")
		return
	}

	for _, invite := range inviteTokens {
		if invite.Valid() {
			fmt.Fprintf(w, "<li>%s %s %s</li>", invite.User, invite.Time, invite.ID)
		}
	}
}

func (state *State) invite(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	if err != nil {
		session, err = cookiestore.New(r, "session-name")
		log.Print(err)
	}

	user := GetUserFromSession(state, session)

	tokenId := r.FormValue("token")

	for _, t := range inviteTokens {
		if t.Valid() && tokenId == t.ID {
			t.Time = time.Unix(0, 0)
			if user == nil {
				user = new(User)
				user.Groups = t.Groups
				user.ID = RandStringRunes(20)
				session.Values["userid"] = user.ID
				session.Save(r, w)
				state.Users = append(state.Users, user)

				http.Redirect(w, r, "/", 303)
			} else {
				log.Print("Already logged in user used an invite ?!?")
			}

			return
		}
	}
}

func saveState(state State) {
	file, err := os.Create("/opt/oauthauth/state/state.toml")
	if err != nil {
		log.Fatal("Unable to save state", err)
	}

	defer file.Close()

	enc := toml.NewEncoder(file)
	enc.Encode(state)
}

func main() {
	init_rand()
	tokens = make([]*Token, 50)

	var config Config
	if _, err := toml.DecodeFile("/opt/oauthauth/config.toml", &config); err != nil {
		log.Fatal(err)
	}

	var state State
	if _, err := toml.DecodeFile("/opt/oauthauth/state/state.toml", &state); err != nil {
		log.Print(err)
	}

	if len(state.CookieStoreSecret) == 0 {
		state.CookieStoreSecret = RandStringRunes(40)
		saveState(state)
	}

	if len(state.Users) == 0 {
		log.Print("Noooo users, we need an admin, generatingadmin invite token")
		token := new(InviteToken)
		token.User = "admin"
		token.Groups = make([]string, 1, 1)
		token.Groups[0] = "admin"

		token.ID = RandStringRunes(30)
		token.Time = time.Now().Add(time.Second * 120)

		inviteTokens = append(inviteTokens, token)

		log.Printf("Visite http://auth.kent.wr25.org/invite?token=%s to get admin", token.ID)
	}

	cookiestore = sessions.NewCookieStore([]byte(state.CookieStoreSecret))
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

	r.HandleFunc("/invite", state.invite)
	r.HandleFunc("/login", state.login)
	r.HandleFunc("/token", state.token)
	r.HandleFunc("/gettoken", state.getToken)
	r.HandleFunc("/gettokeninfo", getTokenInfo)
	r.HandleFunc("/info", state.info)
	r.HandleFunc("/createinvite", state.createInvite)
	r.HandleFunc("/listinvites", state.listPendingInvites)
	r.HandleFunc("/", state.info)

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		log.Fatal(err)
	}
}
