package initializers

import "go-jwt.com/models"

func SynDatabase() {
  // Migrate the schema
  DB.AutoMigrate(&models.User{})
}