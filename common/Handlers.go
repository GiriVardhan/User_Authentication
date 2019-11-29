package handlers

import (
    "html/template"
    "net/http"
    "fmt"
    "time"
    Cassandra "../Cassandra"
    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/securecookie"
)

type userDetails struct {
    Userid   string  
    FirstName string 
    LastName  string 
    Emailid    string
    Password    string
    DateCreated  string
    DateModified string
}

type AllUsersResponse struct {
    Users []userDetails 
    ListLen int
    SuccessMessage string
    FailedMessage string
    IssueMsg string
}

type userCredentials struct {
  EmailId   string
  Password  string
}

type GetPassword struct {
    Password    string 
}

type Response struct {
  WelcomeMessage        string
  ValidateMessage string    
}

type User struct {
    UserId          string `json:"user_id"`
    FirstName       string `json:"first_name"`
    LastName        string `json:"last_name"`
    Email           string `json:"email"`
    Password        string `json:"password"`
}

type Allissues struct {
    IssueMsg string
    SuccessFlag bool
    EmailId string
}

func HashPassword(password string) (string, error) {
        bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
        return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
        err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
        return err == nil
}

func validation(a string, b string, c string, d string) bool {
  if a != b || c != d{
        return false
  }
  return true
}

//********************* Begin Session Handling Code Block ************************
var cookieHandler = securecookie.New(
    securecookie.GenerateRandomKey(64),
    securecookie.GenerateRandomKey(32))
  
func getSession(request *http.Request) (userDetails User) {
    if cookie, err := request.Cookie("user-data"); err == nil {
        cookieValue := make(map[string]User)
        if err = cookieHandler.Decode("user-data", cookie.Value, &cookieValue); err == nil {
            userDetails = cookieValue["user-data"]
        }
    }
    return userDetails
}
  
func setSession(userDetails User, response http.ResponseWriter) {
    value := map[string]User{
        "user-data": userDetails,
    }
    if encoded, err := cookieHandler.Encode("user-data", value); err == nil {
        cookie := &http.Cookie{
            Name:  "user-data",
            Value: encoded,
            Path:  "/",
            MaxAge: 3600,
        }
        http.SetCookie(response, cookie)
    }
}
  
func clearSession(response http.ResponseWriter) {
    cookie := &http.Cookie{
        Name:   "user-data",
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    }
    http.SetCookie(response, cookie)
}
  
  
func clearSessionHandler(response http.ResponseWriter, request *http.Request) {
    clearSession(response)
    http.Redirect(response, request, "/", 302)
}
  

//****************** End Session Handling Code ***************************

//****************** Begin Welcome Page Code *****************************
func WelcomePage(w http.ResponseWriter, r *http.Request) {  
  tmpl, err := template.ParseFiles("templates/welcomePage.html")
  if err != nil {
      fmt.Println(err)
  }

  var welcomeHomePage string
  welcomeHomePage = "Login & Registration Forms"
  
  tmpl.Execute(w, Response{WelcomeMessage: welcomeHomePage})
}
//****************** End Welcome Page Code *****************************


//****************** Begin User Login Page *****************************
func LoginPage(w http.ResponseWriter, r *http.Request) {  
  tmpl, err := template.ParseFiles("templates/loginPage.html")
  if err != nil {
      fmt.Println(err)
  }

  credentials := userCredentials{
        EmailId:   r.FormValue("emailId"),
    Password:   r.FormValue("password"), 
  }

  m := map[string]interface{}{}
  var password string = ""
  var emailId string
  var fname string
  var userId string
  var user User

  iter := Cassandra.Session.Query("SELECT email_id, password, first_name,user_id FROM user_details WHERE email_id = ? ALLOW FILTERING", credentials.EmailId).Iter() 
  for iter.MapScan(m) {
    password = m["password"].(string)
    emailId = m["email_id"].(string)
    fname = m["first_name"].(string)
    userId = m["user_id"].(string)
    user = User{
        UserId: userId,
        FirstName: fname,
    }
  }

  var emailValidation string

  _userIsValid := CheckPasswordHash(credentials.Password, password)

  fmt.Println(_userIsValid);

  if !validation(emailId, credentials.EmailId, password, credentials.Password) {
    emailValidation = "Please enter valid Email ID/Password"
  }

  if _userIsValid {
    setSession(user, w)
    http.Redirect(w, r, "/dashboard", http.StatusFound)
  }

  var welcomeLoginPage string
  welcomeLoginPage = "Login Page"

  tmpl.Execute(w, Response{WelcomeMessage: welcomeLoginPage, ValidateMessage: emailValidation})   
  
}
//***************************** End User Login Page Code *******************************************


//*********************** Begin Registration Page Code *********************************************
func RegistrationPage(w http.ResponseWriter, r *http.Request) {
        var err error
        var flag bool

        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        t := template.Must(template.ParseFiles("templates/registrationPage.html"))

        if err != nil {
        fmt.Fprintf(w, "Unable to load template")
        }

        if r.Method != http.MethodPost {
            t.Execute(w, nil)
            return
        }

        dt := time.Now() 
        ti := time.Now()
        
        details := User{
            UserId:     r.FormValue("userid"),
                        FirstName:  r.FormValue("fname"),
                        LastName:   r.FormValue("lname"),
            Email:      r.FormValue("email"),
            Password:   r.FormValue("pwd"),
        }
        msg := checkDuplicateEmail(details.Email)

        hash, _ := HashPassword(details.Password)
                
        if msg == ""{
            fmt.Println(" **** Inserting a record ****")
            if err := Cassandra.Session.Query("INSERT INTO user_details(user_id, first_name, last_name, email_id,password,date_created,date_modified) VALUES(?, ?, ?, ?,?,?,?)",
            details.UserId, details.FirstName, details.LastName, details.Email, hash, dt, ti).Exec(); err != nil {
                fmt.Println("Error while inserting Emp")
                fmt.Println(err)
            } else {        
                flag = true
                //w.Write([]byte("<script>alert('User Registered Successfully');window.location = '/login'</script>"))                                         
            }

        }   
    t.Execute(w, Allissues{EmailId: details.Email, IssueMsg: msg, SuccessFlag: flag} )
}
//*********************** End Registration Page Code ****************************************

//*********************** Start User Dashboard Code *****************************************
func UserDashBoard(w http.ResponseWriter, r *http.Request) {  
    t, err := template.ParseFiles("templates/user-dashboard.html")
      if err != nil {
          fmt.Println(err)
      }
      userDetails := getSession(r)
      fmt.Println(userDetails)

      items := struct {
          Name string
          Homepage string
          
      }{
        Name : userDetails.FirstName,
        Homepage: "Your Dashboard",
        
      }
      t.Execute(w, items)
  }
//*********************** End User Dashboard Code *****************************************


//**************** Begin Email Updation Code *****************************************
func UpdateEmail(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    t, err := template.ParseFiles("templates/update-email.html")
    userData := getSession(r)
    if err != nil {
        fmt.Println(err) // Ugly debug output
        w.WriteHeader(http.StatusInternalServerError) // Proper HTTP response
        return
      }
    
      if err != nil {
          fmt.Println(err)
      }
      if r.Method != http.MethodPost {
        t.Execute(w, nil)
        return
    }

    details := userDetails{
        Userid: userData.UserId,
        Emailid: r.FormValue("emailid"),
    }
    msg:= checkDuplicateEmail(details.Emailid)
    var empList []userDetails
    m := map[string]interface{}{}
    var successMessage string
    var failedMessage string
    //var flag bool

    iter := Cassandra.Session.Query("SELECT * FROM user_details WHERE user_id = ?", details.Userid).Iter() 
    for iter.MapScan(m) {
        empList = append(empList, userDetails{
                    Userid:    m["user_id"].(string),
                    FirstName: m["first_name"].(string),
                    LastName:  m["last_name"].(string),
                    Password:  m["password"].(string),
        })
        m = map[string]interface{}{}
    }

    listLen := len(empList);

    if(listLen > 0) {
        if msg == ""{
        if err := Cassandra.Session.Query("UPDATE user_details SET email_id = ? WHERE  user_id = ?", details.Emailid,details.Userid).Exec(); 
        err != nil {
            fmt.Println("Error while updating user email")
            fmt.Println(err)
        } else {
            successMessage = "User Email Id Updated Successfully"
            w.Write([]byte("<script>alert('Email Id  Updated Successfully,please login');window.location = '/login'</script>"))
        }
    }else {
        //flag = true
    } 
    }else {
        failedMessage = "There is no User with that User Id"
    }
    t.Execute(w, AllUsersResponse{ListLen: listLen, SuccessMessage: successMessage, FailedMessage: failedMessage,IssueMsg: msg})  
}
//**************** End Email Updation Code *****************************************


//****************** Begin Check Duplicate Email Code ******************************
func checkDuplicateEmail(email string) (message string) {
            
        fmt.Println(" **** get count ****")
        var count int 
        iter := Cassandra.Session.Query("SELECT count(*) FROM user_details where email_id = ? allow filtering", email ).Iter();
        for iter.Scan(&count) {
        }

        if count > 0 {
            message = "Email already exists"
        }

    return message   
}
//****************** End Check Duplicate Email Code ******************************


//************************ Begin Password Update Code *****************************************
func PasswordUpdate(w http.ResponseWriter, r *http.Request) {  
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    t, err := template.ParseFiles("templates/passwordupdate.html")
    userData := getSession(r)
    if err != nil {
        fmt.Println(err) // Ugly debug output
        w.WriteHeader(http.StatusInternalServerError) // Proper HTTP response
        return
      }
    
      if err != nil {
          fmt.Println(err)
      }
      if r.Method != http.MethodPost {
        t.Execute(w, nil)
        return
    }

    details := userDetails{
        Userid: userData.UserId,
        Password: r.FormValue("pwd2"),
    }

    password := details.Password
    hash, _ := HashPassword(password) // ignore error for the sake of simplicity

    fmt.Println("Password:", password)
    fmt.Println("Hash:    ", hash)

    match := CheckPasswordHash(password, hash)
    fmt.Println("Match:   ", match)
    
    var empList []userDetails
    m := map[string]interface{}{}
    var successMessage string
    var failedMessage string
    iter := Cassandra.Session.Query("SELECT * FROM user_details WHERE user_id = ?", details.Userid).Iter() 
    for iter.MapScan(m) {
        empList = append(empList, userDetails{
                    Userid:    m["user_id"].(string),
                    FirstName: m["first_name"].(string),
                    LastName:  m["last_name"].(string),
                    Password:  m["password"].(string),
        })
        m = map[string]interface{}{}
    }

    listLen := len(empList);

    if(listLen > 0) {
        if err := Cassandra.Session.Query("UPDATE user_details SET password = ? WHERE  user_id = ?", hash,details.Userid).Exec(); 
        err != nil {
            fmt.Println("Error while updating  password")
            fmt.Println(err)
        } else {
            successMessage = "Password Updated Successfully"
            w.Write([]byte("<script>alert('Password Updated Successfully,please login');window.location = '/'</script>"))
        }
        
    } else {
        failedMessage = "There is no User with that User Id"
    }
    t.Execute(w, AllUsersResponse{ListLen: listLen, SuccessMessage: successMessage, FailedMessage: failedMessage})  
}
//************************ End Password Update Code *****************************************
