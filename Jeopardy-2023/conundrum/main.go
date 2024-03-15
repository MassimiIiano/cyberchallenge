package main

import (
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("session"))

// Random
var veryEntropicArray = [20]uint64{1792, 1313, 3480, 1151, 1302, 1582, 9311,
	3741, 1358, 1049, 1254, 1732, 1289, 1524, 8608, 1986, 1289, 7144, 1585, 1487}

func main() {
	r := mux.NewRouter()

	r.Handle("/", http.FileServer(http.Dir("./public/views")))
	r.PathPrefix("/static/").
		Handler(http.FileServer(http.Dir("./public/views")))
	r.HandleFunc("/random", entropy).
		Methods("POST").
		Schemes("http")

	http.ListenAndServe("0.0.0.0:8080", r)
}

func entropy(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Reading index from session status
	session_index := session.Values["index"]
	var array_index = 0
	if idx, ok := session_index.(int); ok {
		session.Values["index"] = (idx + 1) % 20
		array_index = idx % 20
	} else {
		session.Values["index"] = 1
	}
	session.Save(r, w)

	var guess, _ = ioutil.ReadAll(r.Body)
	var guess_str = string(guess)

	// Getting number
	var entropic_result = strconv.FormatUint(veryEntropicArray[array_index], 10)

	// Checking the guess
	if guess_str == entropic_result {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(os.Getenv("FLAG")))
	} else {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("You fool!! The answer was " + entropic_result))
	}
}
