package broparser

import (
	"fmt"
	"log"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func NewPostgresDB(host, port, user, password, dbname string) *gorm.DB {
	pqinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := gorm.Open("postgres", pqinfo)
	if err != nil {
		panic(err)
	}

	log.Println("database connected")

	db.AutoMigrate(&ConnRecord{})
	db.AutoMigrate(&DNSRecord{})

	return db
}
