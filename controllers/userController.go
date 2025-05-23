package controllers

import (
	"errors" // Added for errors.Is
	"net/http"
	"os"
	"regexp"
	"strconv"
	// "strings" // No longer strictly needed after refactoring UpdateUser email check
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go-jwt.com/initializers"
	"go-jwt.com/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm" // Added for gorm.ErrRecordNotFound
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

	// Validate Email
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	if !regexp.MustCompile(emailRegex).MatchString(body.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email format"})
		return
	}

	// Validate Password length
	if len(body.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters long"})
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

	// Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})

		return
	}

	// Compare sent in pass with saved user pass hash 
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})

		return
	}
	// Generate JWT token
	jwtExpirationHoursStr := os.Getenv("JWT_EXPIRATION_HOURS")
	expirationHours, err := strconv.Atoi(jwtExpirationHoursStr)
	if err != nil || expirationHours <= 0 {
		expirationHours = 720 // Default to 30 days (720 hours)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * time.Duration(expirationHours)).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret key
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign token"})

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

// GetUsers handles fetching all users
func GetUsers(c *gin.Context) {
	var users []models.User
	result := initializers.DB.Find(&users)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}

	// Exclude passwords from the response
	var publicUsersData []gin.H
	for _, user := range users {
		publicUsersData = append(publicUsersData, gin.H{"id": user.ID, "email": user.Email})
	}
	c.JSON(http.StatusOK, publicUsersData)
}

// GetUser handles fetching a single user by ID
func GetUser(c *gin.Context) {
	requestedIDStr := c.Param("id")
	requestedID, err := strconv.ParseUint(requestedIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID format"})
		return
	}

	authCtxUser, exists := c.Get("user")
	if !exists {
		// This should ideally not happen if RequireAuth middleware is working correctly
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authenticated user not found in context"})
		return
	}
	authenticatedUser := authCtxUser.(models.User)

	// Authorization: Users can only get their own data
	if authenticatedUser.ID != uint(requestedID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you are not authorized to view this user"})
		return
	}

	var user models.User
	result := initializers.DB.First(&user, uint(requestedID))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
}

// UpdateUser handles updating a user's information
func UpdateUser(c *gin.Context) {
	requestedIDStr := c.Param("id")
	requestedID, err := strconv.ParseUint(requestedIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID format"})
		return
	}

	authCtxUser, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authenticated user not found in context"})
		return
	}
	authenticatedUser := authCtxUser.(models.User)

	// Authorization: Users can only update their own data
	if authenticatedUser.ID != uint(requestedID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you are not authorized to update this user"})
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Validate new email format if provided
	if body.Email != "" {
		emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
		if !regexp.MustCompile(emailRegex).MatchString(body.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email format"})
			return
		}
	}

	var user models.User
	result := initializers.DB.First(&user, uint(requestedID))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user for update"})
		}
		return
	}

	// Update user's email if a new one is provided and it's different
	if body.Email != "" && body.Email != user.Email {
		// Pre-emptively check if the new email is already taken by another user
		var existingUserWithNewEmail models.User
		emailCheckResult := initializers.DB.Where("email = ? AND id != ?", body.Email, user.ID).First(&existingUserWithNewEmail)
		
		if emailCheckResult.Error == nil { 
			// Found another user with this email address
			c.JSON(http.StatusConflict, gin.H{"error": "email address already in use"})
			return
		}
		// If the error is anything other than "record not found", it's an unexpected DB issue
		if !errors.Is(emailCheckResult.Error, gorm.ErrRecordNotFound) { 
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify email uniqueness"})
			return
		}

		// Proceed with the update
		user.Email = body.Email // Update the email in the current user model
		updateResult := initializers.DB.Save(&user) // Save the whole user model, GORM handles partial updates for changed fields
		if updateResult.Error != nil {
			// This could still fail due to a race condition if another request set the email in between,
			// so a general "failed to update" or a more specific check for unique constraint can be here.
			// For simplicity, a general error is often sufficient after a pre-emptive check.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
}

// DeleteUser handles deleting a user
func DeleteUser(c *gin.Context) {
	requestedIDStr := c.Param("id")
	requestedID, err := strconv.ParseUint(requestedIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID format"})
		return
	}

	authCtxUser, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authenticated user not found in context"})
		return
	}
	authenticatedUser := authCtxUser.(models.User)

	// Authorization: Users can only delete their own data
	if authenticatedUser.ID != uint(requestedID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you are not authorized to delete this user"})
		return
	}

	var user models.User
	result := initializers.DB.First(&user, uint(requestedID))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user for deletion"})
		}
		return
	}

	// Perform the delete operation. GORM handles soft delete due to gorm.Model.
	deleteResult := initializers.DB.Delete(&user)
	if deleteResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	
	// For soft deletes, a successful .Delete call without an error is generally enough.
	// Checking RowsAffected can be misleading as it might be 0 if the record was already soft-deleted.
	// If RowsAffected is critical, ensure it behaves as expected with your GORM version and soft delete setup.
	// We are removing the RowsAffected check for simplicity with soft deletes.

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}