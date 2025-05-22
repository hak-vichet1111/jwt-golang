package initializers

import "go-jwt.com/models"

func SyncDatabase() {
  // Migrate the schema
  DB.AutoMigrate(&models.User{})
}