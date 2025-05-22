package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"go-jwt.com/initializers"
	"go-jwt.com/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var testDB *gorm.DB
var router *gin.Engine

// Helper function to generate a JWT token
func generateTestToken(userID uint, secretKey string, expirationDelta time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(expirationDelta).Unix(),
	})
	return token.SignedString([]byte(secretKey))
}

// Dummy handler to be called after RequireAuth
func dummyHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "passed", "userID": user.(models.User).ID})
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	// Set a dummy secret for testing token generation
	os.Setenv("SECRET", "testsecret")
	// Set a dummy JWT_EXPIRATION_HOURS (not directly used by RequireAuth, but good practice if other parts of app are initialized)
	os.Setenv("JWT_EXPIRATION_HOURS", "1")


	var err error
	dbPath := "test_database_middleware.db"
	os.Remove(dbPath)

	testDB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to test database: " + err.Error())
	}

	originalDB := initializers.DB
	initializers.DB = testDB

	err = testDB.AutoMigrate(&models.User{})
	if err != nil {
		panic("Failed to migrate test database: " + err.Error())
	}

	router = gin.New()
	// Apply middleware to a test group
	authGroup := router.Group("/testauth")
	authGroup.Use(RequireAuth)
	authGroup.GET("", dummyHandler) // Test route

	exitVal := m.Run()

	initializers.DB = originalDB
	sqlDB, _ := testDB.DB()
	sqlDB.Close()
	os.Remove(dbPath)

	os.Exit(exitVal)
}

func clearUserTable() {
	testDB.Exec("DELETE FROM users")
	// Add other tables if necessary, e.g., testDB.Exec("DELETE FROM some_other_table")
}

func createUserForTest(email string, password string) (models.User, error) {
	user := models.User{Email: email, Password: password} // Password hashing not needed for these tests
	result := testDB.Create(&user)
	return user, result.Error
}


// --- Test Cases ---

func TestRequireAuthSuccess(t *testing.T) {
	clearUserTable()
	user, err := createUserForTest("auth.success@example.com", "password123")
	assert.NoError(t, err)

	tokenString, err := generateTestToken(user.ID, os.Getenv("SECRET"), time.Hour*1) // Valid for 1 hour
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/testauth", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenString})
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "passed", response["message"])
	// userID in response is float64 due to JSON unmarshalling, so cast user.ID
	assert.Equal(t, float64(user.ID), response["userID"])
}

func TestRequireAuthNoCookie(t *testing.T) {
	clearUserTable()
	// No user creation or token needed for this test

	req, _ := http.NewRequest(http.MethodGet, "/testauth", nil)
	// No cookie added
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "missing authorization token", response["error"])
}

func TestRequireAuthInvalidToken(t *testing.T) {
	clearUserTable()
	
	invalidTokenString := "this.is.not.a.valid.jwt.token"

	req, _ := http.NewRequest(http.MethodGet, "/testauth", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: invalidTokenString})
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid token", response["error"])
}


func TestRequireAuthExpiredToken(t *testing.T) {
	clearUserTable()
	user, err := createUserForTest("auth.expired@example.com", "password123")
	assert.NoError(t, err)

	// Token expired 1 hour ago
	tokenString, err := generateTestToken(user.ID, os.Getenv("SECRET"), -time.Hour*1) 
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/testauth", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenString})
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "token expired", response["error"])
}

func TestRequireAuthTokenForNonExistentUser(t *testing.T) {
	clearUserTable()
	
	nonExistentUserID := uint(99999) // Assume this ID does not exist
	tokenString, err := generateTestToken(nonExistentUserID, os.Getenv("SECRET"), time.Hour*1)
	assert.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/testauth", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenString})
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	// The error message from the code is "invalid token: user not found"
	assert.Equal(t, "invalid token: user not found", response["error"])
}
