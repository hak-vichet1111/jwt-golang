package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go-jwt.com/initializers"
	"go-jwt.com/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var testDB *gorm.DB
var router *gin.Engine

// TestMain is executed before any test in the package
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	var err error
	// Using an in-memory SQLite database for testing
	// Using a file-based SQLite for easier inspection during development: "test.db"
	// To ensure a clean state, delete the db file if it exists
	dbPath := "test_database_usercontroller.db"
	os.Remove(dbPath) 

	testDB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to test database: " + err.Error())
	}

	// Store the original DB and replace it with the testDB
	originalDB := initializers.DB
	initializers.DB = testDB

	// Run migrations
	err = testDB.AutoMigrate(&models.User{})
	if err != nil {
		panic("Failed to migrate test database: " + err.Error())
	}

	// Setup router
	router = gin.New()
	router.POST("/signup", Signup)
	router.POST("/login", Login)
	// Add other routes if needed for more complex tests e.g. Validate

	// Run tests
	exitVal := m.Run()

	// Restore the original DB
	initializers.DB = originalDB

	// Clean up: close DB connection and remove the SQLite file
	sqlDB, _ := testDB.DB()
	sqlDB.Close()
	os.Remove(dbPath)


	os.Exit(exitVal)
}

func clearUserTable() {
	testDB.Exec("DELETE FROM users")
}


func TestSignupSuccess(t *testing.T) {
	clearUserTable() // Ensure table is clean

	payload := gin.H{
		"email":    "test.success@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user created successfully", response["message"])

	// Verify user in DB
	var user models.User
	result := testDB.Where("email = ?", "test.success@example.com").First(&user)
	assert.NoError(t, result.Error)
	assert.Equal(t, "test.success@example.com", user.Email)
}

func TestSignupInvalidEmail(t *testing.T) {
	clearUserTable()

	payload := gin.H{
		"email":    "invalid-email",
		"password": "password123",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid email format", response["error"])
}

func TestSignupShortPassword(t *testing.T) {
	clearUserTable()

	payload := gin.H{
		"email":    "test.shortpass@example.com",
		"password": "pass", // Too short
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "password must be at least 8 characters long", response["error"])
}

func TestSignupExistingEmail(t *testing.T) {
	clearUserTable()

	// Create initial user
	initialPayload := gin.H{
		"email":    "existing.user@example.com",
		"password": "password123",
	}
	initialBody, _ := json.Marshal(initialPayload)
	initialReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(initialBody))
	initialReq.Header.Set("Content-Type", "application/json")
	initialW := httptest.NewRecorder()
	router.ServeHTTP(initialW, initialReq)
	assert.Equal(t, http.StatusOK, initialW.Code) // Ensure first user is created

	// Attempt to sign up with the same email
	payload := gin.H{
		"email":    "existing.user@example.com",
		"password": "anotherPassword123",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The current implementation returns 500 for "failed to create user"
	// due to the unique constraint on email in the User model.
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "failed to create user", response["error"])
}

func TestLoginSuccess(t *testing.T) {
	clearUserTable()

	// 1. Signup a user first
	signupPayload := gin.H{
		"email":    "login.success@example.com",
		"password": "password123",
	}
	signupBody, _ := json.Marshal(signupPayload)
	signupReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(signupBody))
	signupReq.Header.Set("Content-Type", "application/json")
	signupW := httptest.NewRecorder()
	router.ServeHTTP(signupW, signupReq)
	assert.Equal(t, http.StatusOK, signupW.Code)


	// 2. Login with the created user
	loginPayload := gin.H{
		"email":    "login.success@example.com",
		"password": "password123",
	}
	loginBody, _ := json.Marshal(loginPayload)

	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	// Check for Authorization cookie
	cookieFound := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "Authorization" {
			cookieFound = true
			assert.NotEmpty(t, cookie.Value, "Authorization cookie should not be empty")
			break
		}
	}
	assert.True(t, cookieFound, "Authorization cookie not found")

	// Check response body (should be empty JSON `{}`, or specific success message if any)
	var response map[string]interface{} // Use interface{} for empty JSON
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Len(t, response, 0, "Login response body should be empty JSON object")
}

func TestLoginNonExistentEmail(t *testing.T) {
	clearUserTable()

	payload := gin.H{
		"email":    "nonexistent@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "user not found", response["error"])
}

func TestLoginIncorrectPassword(t *testing.T) {
	clearUserTable()

	// 1. Signup a user first
	signupPayload := gin.H{
		"email":    "login.fail@example.com",
		"password": "correctPassword123",
	}
	signupBody, _ := json.Marshal(signupPayload)
	signupReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(signupBody))
	signupReq.Header.Set("Content-Type", "application/json")
	signupW := httptest.NewRecorder()
	router.ServeHTTP(signupW, signupReq)
	assert.Equal(t, http.StatusOK, signupW.Code)


	// 2. Attempt login with incorrect password
	loginPayload := gin.H{
		"email":    "login.fail@example.com",
		"password": "incorrectPassword",
	}
	loginBody, _ := json.Marshal(loginPayload)

	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "invalid email or password", response["error"])
}
