package main

import (
    "net/http"
    "github.com/gorilla/mux"
    common "./common"
)


func main() {
    router := mux.NewRouter().StrictSlash(true)
    router.HandleFunc("/", common.WelcomePage)
    router.HandleFunc("/login", common.LoginPage)
    router.HandleFunc("/registration", common.RegistrationPage)
    router.HandleFunc("/dashboard", common.UserDashBoard)
    router.HandleFunc("/updateEmail", common.UpdateEmail)
    router.HandleFunc("/passwordUpdate", common.PasswordUpdate)
    http.ListenAndServe(":8080", router)
}



