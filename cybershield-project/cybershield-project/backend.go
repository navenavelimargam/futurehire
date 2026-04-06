package main

import (
	"fmt"
	"net/http"
)

func backendMain() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Backend server is working")
	})

	fmt.Println("Backend running on port 8080")

	http.ListenAndServe(":8080", nil)
}
