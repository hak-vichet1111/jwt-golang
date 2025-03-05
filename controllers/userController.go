package controllers

import (
	// "go/token"
	"net/http"
	"os"
	"time"

	// "os/user"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go-jwt.com/initializers"
	"go-jwt.com/models"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	// Get the Email/Password off request body
	var body struct {
		Email string 
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})

		return
	}

	// Hash the password
	hash, err :=bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		
		return	
	}


	// Create the user 
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user created successfully"})

	// Respose 
}

func Login(c *gin.Context) {
	// Get the Email/Password off request body
	var body struct {
		Email string 
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})

		return
	}

	// Loop up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})

		return
	}

	// Compare sent in pass with saved user pass hash 
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})

		return
	}
	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.ID,
		"exp":   time.Now().Add(time.Hour * 24 * 30).Unix(),
		})
	

	// Sign and get the complete encoded token as a string using the secrete key
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})

		return
	}

	// send it back 
	c.SetSameSite(http.SameSiteDefaultMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})

}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{"message": user})
}