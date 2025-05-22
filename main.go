package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go-jwt.com/controllers"
	"go-jwt.com/initializers"
	"go-jwt.com/middleware"
	// "go-jwt.com/middleware"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
  initializers.SyncDatabase()
}

func main() {
	fmt.Println("Hello 2")

	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	// r.GET("/ping", func(c *gin.Context) {
	// 	c.JSON(200, gin.H{
	// 		"message": "pong",
	// 	})
	// })
	r.Run() // listen and serve on 0.0.0.0:3000
}