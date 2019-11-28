package Cassandra

import (
	"github.com/gocql/gocql"
	"fmt"
        "database/sql"
)

// Session holds our connection to Cassandra
var Session *gocql.Session
var db *sql.DB

func init() {
	var err error

	cluster := gocql.NewCluster("172.17.0.2")
	cluster.Keyspace = "userdb"
	Session, err = cluster.CreateSession()
	if err != nil {
		panic(err)
	}
	fmt.Println("cassandra init done")
}
