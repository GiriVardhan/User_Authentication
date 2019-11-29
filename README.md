# user_authentication
Setup the below keyspace and table on Cassandra DB

CREATE KEYSPACE userdb WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };

CREATE TABLE userdb.user_details (
   user_id text PRIMARY KEY,
   date_created date,
   date_modified timestamp,
   email_id text,
   first_name text,
   last_name text,
   password text
)

#To create docker image run the below commands from project root directory

$ go get github.com/gocql/gocql 
$ go get github.com/gorilla/mux
$ go get golang.org/x/crypto/bcrypt
$ go get github.com/gorilla/securecookie

Command to build GO apllication

$ go build
Get the executable generated from the above command and run below command to create docer image

docker build -t executable .
Please update IP address in the database connection section accordingly.

cluster := gocql.NewCluster("172.18.0.3")
