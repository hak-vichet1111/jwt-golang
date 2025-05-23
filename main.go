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

	// User routes (protected)
	userRoutes := r.Group("/users")
	userRoutes.Use(middleware.RequireAuth)
	{
		userRoutes.GET("", controllers.GetUsers)
		userRoutes.GET("/:id", controllers.GetUser)
		userRoutes.PUT("/:id", controllers.UpdateUser)
		userRoutes.DELETE("/:id", controllers.DeleteUser)
	}

	// r.GET("/ping", func(c *gin.Context) {
	// 	c.JSON(200, gin.H{
	// 		"message": "pong",
	// 	})
	// })
	r.Run() // listen and serve on 0.0.0.0:3000
}