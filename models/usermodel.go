package models

type User struct {
	ID       int `gorm:primaryKey`
	Name     string
	Email    string
	Password string
}
