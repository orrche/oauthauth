package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func StaticFS(r *mux.Router) {
	// http.Handle("/", http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: "static"}))
	http.Handle("/static/", http.FileServer(assetFS()))
	fmt.Printf("Hello World")

}
