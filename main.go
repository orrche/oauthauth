package main

//go:generate go-bindata-assetfs static/... template
// # // go:generate go-bindata template

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/arschles/go-bindata-html-template"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var oauthconf *oauth2.Config
var cookiestore *sessions.CookieStore

type Action interface {
	Act(w http.ResponseWriter, r *http.Request)
}

type RedirectAction struct {
	URL string
}

func (ra RedirectAction) Act(w http.ResponseWriter, r *http.Request) {
	log.Printf("URL: %s", ra.URL)
	http.Redirect(w, ra.URL, 303)
}

type actionHolder struct {
	action Action
	state  string
}

var actions [50]actionHolder

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
	type Info struct {
		GoogleLink string
		Title      string
	}

	ta := new(RedirectAction)
	ta.URL = "/info"
	atoken := RandStringRunes(30)

	for i, a := range actions {
		if a.action == nil {
			actions[i].action = ta
			actions[i].state = atoken
			break
		}
	}

	info := Info{oauthconf.AuthCodeURL(atoken), "Login"}

	tmpl := readTemplateFile("template/login.html")
	err := tmpl.Execute(w, info)
	failOnErr(err, w, r)
}

func decodeIdToken(idToken string) (gplusID string, err error) {
	var set ClaimSet
	if idToken != "" {
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

func readTemplateFile(filename string) *template.Template {
	return template.Must(template.New("base", Asset).ParseFiles("template/base.html", filename))
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

	stateToken := r.FormValue("state")
	for _, action := range actions {
		if action.state == stateToken {
			action.action.Act(w, r)
			action.action = nil
			return
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session, _ := cookiestore.Get(r, "session-name")

	user := GetUserFromSession(state, session)

	if user == nil {
		http.Redirect(w, r, "/login", 303)
		return
	}

	t := genereateToken()
	t.User = user.ID

	u, err := url.Parse(r.FormValue("returl"))
	log.Print(u)
	failOnErr(err, w, r)
	q := u.Query()
	q.Set("token", t.ID)
	u.RawQuery = q.Encode()
	log.Print(u)

	http.Redirect(w, r, u.String(), 302)
}

func (state *State) getGroupsFromToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	tokenId := r.FormValue("token")

	for _, t := range tokens {
		if t.Valid() && tokenId == t.ID {
			user := state.GetUserFromId(t.User)
			if r.FormValue("user") == "" || r.FormValue("user") == user.ID {
				type Info struct {
					Groups []string
				}
				info := Info{user.Groups}

				enc := toml.NewEncoder(w)
				enc.Encode(info)
			} else if !user.IsMemberOf("admin") {
				data, err := json.Marshal(state.GetUserFromId(r.FormValue("user")).Groups)
				failOnErr(err, w, r)

				w.Write(data)
			}
			return
		}
	}
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
	session, _ := cookiestore.Get(r, "session-name")

	type Info struct {
		User   *User
		Title  string
		Tokens []*Token
	}

	info := Info{GetUserFromSession(state, session), "Info", tokens}

	if info.User == nil {
		http.Redirect(w, r, "/login", 302)
	} else {
		tmpl := readTemplateFile("template/info.html")
		err := tmpl.Execute(w, info)
		failOnErr(err, w, r)
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

func (state *State) getUsers(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	failOnErr(err, w, r)

	user := GetUserFromSession(state, session)

	if user.IsMemberOf("admin") {
		data, err := json.Marshal(state.Users)
		failOnErr(err, w, r)
		w.Write(data)
	}
}

func (state *State) getGroups(w http.ResponseWriter, r *http.Request) {
	session, err := cookiestore.Get(r, "session-name")
	failOnErr(err, w, r)

	user := GetUserFromSession(state, session)
	if r.FormValue("user") == "" || r.FormValue("user") == user.ID {
		data, err := json.Marshal(user.Groups)
		failOnErr(err, w, r)

		w.Write(data)
	} else if !user.IsMemberOf("admin") {
		data, err := json.Marshal(state.GetUserFromId(r.FormValue("user")).Groups)
		failOnErr(err, w, r)

		w.Write(data)
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
		type Info struct {
			Groups []string
			Title  string
		}

		info := Info{[]string{"admin"}, "Create Invite"}

		tmpl := readTemplateFile("template/createinvite.html")
		err := tmpl.Execute(w, info)
		failOnErr(err, w, r)
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
	session, _ := cookiestore.Get(r, "session-name")
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

	StaticFS(r)
	http.Handle("/", r)

	r.HandleFunc("/invite", state.invite)
	r.HandleFunc("/login", state.login)
	r.HandleFunc("/token", state.token)
	r.HandleFunc("/gettoken", state.getToken)
	r.HandleFunc("/gettokeninfo", getTokenInfo)
	r.HandleFunc("/getgroupsfromtoken", state.getGroupsFromToken)
	r.HandleFunc("/getgroups", state.getGroups)
	r.HandleFunc("/getusers", state.getUsers)
	r.HandleFunc("/info", state.info)
	r.HandleFunc("/createinvite", state.createInvite)
	r.HandleFunc("/listinvites", state.listPendingInvites)
	r.HandleFunc("/", state.info)

	log.Print("Server started")
	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		log.Fatal(err)
	}
}
