package controllers

import (
	"bytes"
	"encoding/json"
	"errors" // For gorm.ErrRecordNotFound check
	"fmt"    // For Sprintf in TestMain if needed by middleware.RequireAuth's internals (though unlikely for tests)
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings" // For error message checking if needed
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"go-jwt.com/initializers"
	"go-jwt.com/middleware" // Import actual middleware
	"go-jwt.com/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var testDB *gorm.DB
var router *gin.Engine

// TestMain is executed before any test in the package
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Setenv("SECRET", "test_secret_for_user_controller_tests_final") // Consistent secret

	var err error
	dbPath := "test_usercontroller.db" // Use a distinct name
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
	router.POST("/signup", Signup)
	router.POST("/login", Login)
	// The /validate route is protected by RequireAuth in main.go.
	// If tests for Validate controller were here, it would also need RequireAuth.
	// For now, it's not tested in this file, so we can omit its setup or use a placeholder if needed.
	// router.GET("/validate", middleware.RequireAuth, Validate)

	userRoutes := router.Group("/users")
	userRoutes.Use(middleware.RequireAuth) // USING ACTUAL RequireAuth MIDDLEWARE
	{
		userRoutes.GET("", GetUsers)
		userRoutes.GET("/:id", GetUser)
		userRoutes.PUT("/:id", UpdateUser)
		userRoutes.DELETE("/:id", DeleteUser)
	}

	exitVal := m.Run()

	initializers.DB = originalDB // Restore original DB
	sqlDB, _ := testDB.DB()
	sqlDB.Close()
	os.Remove(dbPath) // Clean up test DB file
	os.Exit(exitVal)
}

func clearUserTable() {
	testDB.Exec("DELETE FROM users")
}

func generateTestTokenForUser(userID uint, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})
	return token.SignedString([]byte(secretKey))
}

func createUserInDB(email string, password string) (models.User, error) {
	// Password hashing isn't strictly necessary for these tests if auth relies solely on token.
	user := models.User{Email: email, Password: "hashedDummyPassword"}
	result := testDB.Create(&user)
	return user, result.Error
}

// --- Existing Tests (Signup, Login) - Assume these are correct ---
func TestSignupSuccess(t *testing.T) {
	clearUserTable() 
	payload := gin.H{"email":    "test.success@example.com", "password": "password123"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "user created successfully", response["message"])
	var user models.User
	result := testDB.Where("email = ?", "test.success@example.com").First(&user)
	assert.NoError(t, result.Error)
	assert.Equal(t, "test.success@example.com", user.Email)
}

func TestSignupInvalidEmail(t *testing.T) {
	clearUserTable()
	payload := gin.H{"email":    "invalid-email", "password": "password123"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "invalid email format", response["error"])
}

func TestSignupShortPassword(t *testing.T) {
	clearUserTable()
	payload := gin.H{"email":    "test.shortpass@example.com", "password": "pass"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "password must be at least 8 characters long", response["error"])
}

func TestSignupExistingEmail(t *testing.T) {
	clearUserTable()
	initialPayload := gin.H{"email":    "existing.user@example.com", "password": "password123"}
	initialBody, _ := json.Marshal(initialPayload)
	initialReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(initialBody))
	initialReq.Header.Set("Content-Type", "application/json")
	initialW := httptest.NewRecorder()
	router.ServeHTTP(initialW, initialReq)
	assert.Equal(t, http.StatusOK, initialW.Code) 
	payload := gin.H{"email":    "existing.user@example.com", "password": "anotherPassword123"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code) // As per current controller logic
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "failed to create user", response["error"])
}

func TestLoginSuccess(t *testing.T) {
	clearUserTable()
	signupPayload := gin.H{"email":    "login.success@example.com", "password": "password123"}
	signupBody, _ := json.Marshal(signupPayload)
	signupReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(signupBody))
	signupReq.Header.Set("Content-Type", "application/json")
	signupW := httptest.NewRecorder()
	router.ServeHTTP(signupW, signupReq)
	assert.Equal(t, http.StatusOK, signupW.Code)
	loginPayload := gin.H{"email":    "login.success@example.com", "password": "password123"}
	loginBody, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	cookieFound := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "Authorization" {
			cookieFound = true
			assert.NotEmpty(t, cookie.Value)
			break
		}
	}
	assert.True(t, cookieFound)
	var response map[string]interface{} 
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Len(t, response, 0)
}

func TestLoginNonExistentEmail(t *testing.T) {
	clearUserTable()
	payload := gin.H{"email":    "nonexistent@example.com", "password": "password123"}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "user not found", response["error"])
}

func TestLoginIncorrectPassword(t *testing.T) {
	clearUserTable()
	signupPayload := gin.H{"email":    "login.fail@example.com", "password": "correctPassword123"}
	signupBody, _ := json.Marshal(signupPayload)
	signupReq, _ := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(signupBody))
	signupReq.Header.Set("Content-Type", "application/json")
	signupW := httptest.NewRecorder()
	router.ServeHTTP(signupW, signupReq)
	assert.Equal(t, http.StatusOK, signupW.Code)
	loginPayload := gin.H{"email":    "login.fail@example.com", "password": "incorrectPassword"}
	loginBody, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "invalid email or password", response["error"])
}


// --- New Test Cases for /users endpoints ---
func TestGetUsers(t *testing.T) {
	clearUserTable()
	requester, _ := createUserInDB("requester.getall@example.com", "reqPass")
	user1, _ := createUserInDB("user1.getall@example.com", "pass1")
	user2, _ := createUserInDB("user2.getall@example.com", "pass2")
	requesterToken, _ := generateTestTokenForUser(requester.ID, os.Getenv("SECRET"))

	req, _ := http.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: requesterToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	var usersResponse []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &usersResponse)
	assert.Len(t, usersResponse, 3) 
	
	foundUsers := make(map[uint]bool)
	for _, userMap := range usersResponse {
		assert.Contains(t, userMap, "id")
		assert.Contains(t, userMap, "email")
		assert.NotContains(t, userMap, "password")
		foundUsers[uint(userMap["id"].(float64))] = true
	}
	assert.True(t, foundUsers[requester.ID], "Requester not found in GetUsers response")
	assert.True(t, foundUsers[user1.ID], "User1 not found in GetUsers response")
	assert.True(t, foundUsers[user2.ID], "User2 not found in GetUsers response")

	// Test with no users (after clearing again, requester also gone)
	clearUserTable()
	// Need a token from a valid user, even if they are the only one or don't exist after clear for this specific check
	// This case is tricky: if no users exist, no valid token can be made to pass RequireAuth.
	// A "no users" test for GetUsers implies an admin/privileged role not covered by current auth.
	// For now, GetUsers will always return at least the requester if successful.
	// If we clear and try with an old token (user now deleted), RequireAuth gives 401.
	invalidToken, _ := generateTestTokenForUser(requester.ID, os.Getenv("SECRET")) // Requester deleted
	reqNoUsers, _ := http.NewRequest(http.MethodGet, "/users", nil)
	reqNoUsers.AddCookie(&http.Cookie{Name: "Authorization", Value: invalidToken})
	wNoUsers := httptest.NewRecorder()
	router.ServeHTTP(wNoUsers, reqNoUsers)
	assert.Equal(t, http.StatusUnauthorized, wNoUsers.Code) // RequireAuth denies due to non-existent user in token
}

func TestGetUser(t *testing.T) {
	clearUserTable()
	userA, _ := createUserInDB("userA.get@example.com", "passA")
	userB, _ := createUserInDB("userB.get@example.com", "passB")
	tokenUserA, _ := generateTestTokenForUser(userA.ID, os.Getenv("SECRET"))

	// Case 1: User A fetches their own data
	reqOwn, _ := http.NewRequest(http.MethodGet, "/users/"+strconv.FormatUint(uint64(userA.ID), 10), nil)
	reqOwn.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserA})
	wOwn := httptest.NewRecorder()
	router.ServeHTTP(wOwn, reqOwn)
	assert.Equal(t, http.StatusOK, wOwn.Code)
	var userResponse map[string]interface{}
	json.Unmarshal(wOwn.Body.Bytes(), &userResponse)
	assert.Equal(t, float64(userA.ID), userResponse["id"])
	assert.Equal(t, userA.Email, userResponse["email"])

	// Case 2: User A tries to fetch User B's data (Forbidden)
	reqOther, _ := http.NewRequest(http.MethodGet, "/users/"+strconv.FormatUint(uint64(userB.ID), 10), nil)
	reqOther.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserA})
	wOther := httptest.NewRecorder()
	router.ServeHTTP(wOther, reqOther)
	assert.Equal(t, http.StatusForbidden, wOther.Code)
	var errorResponse map[string]string
	json.Unmarshal(wOther.Body.Bytes(), &errorResponse)
	assert.Equal(t, "you are not authorized to view this user", errorResponse["error"])
	
	// Case 3: Fetch non-existent user (token for a user that doesn't exist in DB)
	// RequireAuth itself will return 401 "invalid token: user not found".
	nonExistentUserID := uint(9999)
	tokenForNonExistent, _ := generateTestTokenForUser(nonExistentUserID, os.Getenv("SECRET"))
	reqNonExistent, _ := http.NewRequest(http.MethodGet, "/users/"+strconv.FormatUint(uint64(nonExistentUserID), 10), nil)
	reqNonExistent.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenForNonExistent})
	wNonExistent := httptest.NewRecorder()
	router.ServeHTTP(wNonExistent, reqNonExistent)
	assert.Equal(t, http.StatusUnauthorized, wNonExistent.Code) 
	json.Unmarshal(wNonExistent.Body.Bytes(), &errorResponse)
	assert.Equal(t, "invalid token: user not found", errorResponse["error"])

	// Case 4: User A tries to fetch a user ID that does not exist in DB (e.g. /users/99998)
	// RequireAuth passes for User A, but controller finds no user for 99998.
	// This is only a valid test if User A's ID *is* 99998, otherwise it's forbidden.
	// So, this case is better tested by ensuring User A cannot fetch their own non-existent record *after* it's deleted.
	// Or, if the user ID in path does not match authenticated user, it's forbidden (covered by Case 2).
	// If user ID in path *matches* authenticated user, but that user is not found by controller (e.g. deleted after auth), then 404.
	// This specific test is covered by "Delete Non-Existent User ID" in TestDeleteUser more appropriately.
}

func TestUpdateUser(t *testing.T) {
	clearUserTable()
	userToUpdate, _ := createUserInDB("update.me@example.com", "passwordOriginal")
	otherUser, _ := createUserInDB("other.user.update@example.com", "passwordOther")
	tokenUserToUpdate, _ := generateTestTokenForUser(userToUpdate.ID, os.Getenv("SECRET"))

	// Case 1: Successful update
	updatePayload := gin.H{"email": "updated.email@example.com"}
	body, _ := json.Marshal(updatePayload)
	reqSuccess, _ := http.NewRequest(http.MethodPut, "/users/"+strconv.FormatUint(uint64(userToUpdate.ID), 10), bytes.NewBuffer(body))
	reqSuccess.Header.Set("Content-Type", "application/json")
	reqSuccess.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserToUpdate})
	wSuccess := httptest.NewRecorder()
	router.ServeHTTP(wSuccess, reqSuccess)
	assert.Equal(t, http.StatusOK, wSuccess.Code)
	var updatedUserResp map[string]interface{}
	json.Unmarshal(wSuccess.Body.Bytes(), &updatedUserResp)
	assert.Equal(t, "updated.email@example.com", updatedUserResp["email"])
	var dbUser models.User
	initializers.DB.First(&dbUser, userToUpdate.ID)
	assert.Equal(t, "updated.email@example.com", dbUser.Email)

	// Case 2: Update another user's data (Forbidden)
	reqForbidden, _ := http.NewRequest(http.MethodPut, "/users/"+strconv.FormatUint(uint64(otherUser.ID), 10), bytes.NewBuffer(body))
	reqForbidden.Header.Set("Content-Type", "application/json")
	reqForbidden.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserToUpdate})
	wForbidden := httptest.NewRecorder()
	router.ServeHTTP(wForbidden, reqForbidden)
	assert.Equal(t, http.StatusForbidden, wForbidden.Code)

	// Case 3: Invalid email format
	invalidEmailPayload := gin.H{"email": "invalid-email"}
	bodyInvalid, _ := json.Marshal(invalidEmailPayload)
	reqInvalidEmail, _ := http.NewRequest(http.MethodPut, "/users/"+strconv.FormatUint(uint64(userToUpdate.ID), 10), bytes.NewBuffer(bodyInvalid))
	reqInvalidEmail.Header.Set("Content-Type", "application/json")
	reqInvalidEmail.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserToUpdate})
	wInvalidEmail := httptest.NewRecorder()
	router.ServeHTTP(wInvalidEmail, reqInvalidEmail)
	assert.Equal(t, http.StatusBadRequest, wInvalidEmail.Code)
	var errResp map[string]string
	json.Unmarshal(wInvalidEmail.Body.Bytes(), &errResp)
	assert.Equal(t, "invalid email format", errResp["error"])

	// Case 4: Email already exists for another user
	conflictUser, _:= createUserInDB("existing.forconflict@example.com", "passwordConflict")
	conflictPayload := gin.H{"email": conflictUser.Email} 
	bodyConflict, _ := json.Marshal(conflictPayload)
	reqConflict, _ := http.NewRequest(http.MethodPut, "/users/"+strconv.FormatUint(uint64(userToUpdate.ID), 10), bytes.NewBuffer(bodyConflict))
	reqConflict.Header.Set("Content-Type", "application/json")
	reqConflict.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenUserToUpdate})
	wConflict := httptest.NewRecorder()
	router.ServeHTTP(wConflict, reqConflict)
	assert.Equal(t, http.StatusConflict, wConflict.Code)
	json.Unmarshal(wConflict.Body.Bytes(), &errResp)
	assert.Equal(t, "email address already in use", errResp["error"])

	// Case 5: Update target user that doesn't exist (token for a user that doesn't exist in DB)
	// RequireAuth itself will return 401 "invalid token: user not found".
	nonExistentUpdateUserID := uint(8888)
	tokenForNonExistentUpdate, _ := generateTestTokenForUser(nonExistentUpdateUserID, os.Getenv("SECRET"))
	reqNonExistentUpdate, _ := http.NewRequest(http.MethodPut, "/users/"+strconv.FormatUint(uint64(nonExistentUpdateUserID), 10), bytes.NewBuffer(body))
	reqNonExistentUpdate.Header.Set("Content-Type", "application/json")
	reqNonExistentUpdate.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenForNonExistentUpdate})
	wNonExistentUpdate := httptest.NewRecorder()
	router.ServeHTTP(wNonExistentUpdate, reqNonExistentUpdate)
	assert.Equal(t, http.StatusUnauthorized, wNonExistentUpdate.Code) 
	json.Unmarshal(wNonExistentUpdate.Body.Bytes(), &errResp)
	assert.Equal(t, "invalid token: user not found", errResp["error"])
}

func TestDeleteUser(t *testing.T) {
	clearUserTable()
	// SECRET is set in TestMain

	// --- Sub-test 1: Successful Self-Delete ---
	userForSelfDelete, err := createUserInDB("self.delete@example.com", "password123")
	assert.NoError(t, err)
	tokenForSelfDelete, err := generateTestTokenForUser(userForSelfDelete.ID, os.Getenv("SECRET"))
	assert.NoError(t, err)

	reqSelfDelete, _ := http.NewRequest(http.MethodDelete, "/users/"+strconv.FormatUint(uint64(userForSelfDelete.ID), 10), nil)
	reqSelfDelete.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenForSelfDelete})
	wSelfDelete := httptest.NewRecorder()
	router.ServeHTTP(wSelfDelete, reqSelfDelete)
	assert.Equal(t, http.StatusOK, wSelfDelete.Code)
	var successMsg map[string]string
	json.Unmarshal(wSelfDelete.Body.Bytes(), &successMsg)
	assert.Equal(t, "user deleted successfully", successMsg["message"])

	var dbUserSelfDeleted models.User
	initializers.DB.Unscoped().First(&dbUserSelfDeleted, userForSelfDelete.ID) 
	assert.NotNil(t, dbUserSelfDeleted.DeletedAt, "User should be soft-deleted")
	assert.False(t, dbUserSelfDeleted.DeletedAt.Time.IsZero(), "User DeletedAt should not be zero")


	// --- Sub-test 2: Forbidden Delete (Attempt to delete another user) ---
	actorUser, err := createUserInDB("actor.user.delete@example.com", "passwordActor") 
	assert.NoError(t, err)
	targetUser, err := createUserInDB("target.user.delete@example.com", "passwordTarget") 
	assert.NoError(t, err)
	tokenActor, err := generateTestTokenForUser(actorUser.ID, os.Getenv("SECRET"))
	assert.NoError(t, err)

	reqForbidden, _ := http.NewRequest(http.MethodDelete, "/users/"+strconv.FormatUint(uint64(targetUser.ID), 10), nil)
	reqForbidden.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenActor}) 
	wForbidden := httptest.NewRecorder()
	router.ServeHTTP(wForbidden, reqForbidden)
	assert.Equal(t, http.StatusForbidden, wForbidden.Code)
	var forbiddenResp map[string]string
	json.Unmarshal(wForbidden.Body.Bytes(), &forbiddenResp)
	assert.Equal(t, "you are not authorized to delete this user", forbiddenResp["error"])

	var dbTargetUser models.User
	result := initializers.DB.First(&dbTargetUser, targetUser.ID) 
	assert.NoError(t, result.Error, "TargetUser should still exist and not be soft-deleted")
	if result.Error == nil { 
		assert.True(t, dbTargetUser.DeletedAt.Time.IsZero(), "TargetUser DeletedAt should be zero")
	}


	// --- Sub-test 3: Delete Non-Existent User ID (with a valid token of an existing, active user) ---
	// actorUser (created above) is still valid and their token (tokenActor) is active.
	// actorUser tries to delete a user ID that does not exist in the database.
	nonExistentIDForDelete := uint64(99999)
	var checkNonExistent models.User
	errCheck := initializers.DB.First(&checkNonExistent, nonExistentIDForDelete).Error
	assert.Error(t, errCheck) 
	assert.True(t, errors.Is(errCheck, gorm.ErrRecordNotFound), "User 99999 should not exist before this test part")

	reqDeleteNonExistentID, _ := http.NewRequest(http.MethodDelete, "/users/"+strconv.FormatUint(nonExistentIDForDelete, 10), nil)
	reqDeleteNonExistentID.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenActor}) 
	wDeleteNonExistentID := httptest.NewRecorder()
	router.ServeHTTP(wDeleteNonExistentID, reqDeleteNonExistentID)
	assert.Equal(t, http.StatusNotFound, wDeleteNonExistentID.Code)
	var notFoundResp map[string]string
	json.Unmarshal(wDeleteNonExistentID.Body.Bytes(), &notFoundResp)
	assert.Equal(t, "user not found", notFoundResp["error"])


	// --- Sub-test 4: Attempt Delete Without Token ---
	reqNoToken, _ := http.NewRequest(http.MethodDelete, "/users/"+strconv.FormatUint(uint64(targetUser.ID), 10), nil)
	wNoToken := httptest.NewRecorder()
	router.ServeHTTP(wNoToken, reqNoToken)
	assert.Equal(t, http.StatusUnauthorized, wNoToken.Code)
	var noTokenResp map[string]string
	json.Unmarshal(wNoToken.Body.Bytes(), &noTokenResp)
	assert.Equal(t, "missing authorization token", noTokenResp["error"]) 


	// --- Sub-test 5: Attempt Delete with Token for Non-Existent User ---
	nonExistentUserIDAuth := uint(7777) 
	tokenForNonExistentUserAuth, _ := generateTestTokenForUser(nonExistentUserIDAuth, os.Getenv("SECRET"))
	
	reqNonExistentAuth, _ := http.NewRequest(http.MethodDelete, "/users/"+strconv.FormatUint(uint64(nonExistentUserIDAuth), 10), nil)
	reqNonExistentAuth.AddCookie(&http.Cookie{Name: "Authorization", Value: tokenForNonExistentUserAuth})
	wNonExistentAuth := httptest.NewRecorder()
	router.ServeHTTP(wNonExistentAuth, reqNonExistentAuth)
	assert.Equal(t, http.StatusUnauthorized, wNonExistentAuth.Code) 
	var nonExistentAuthErrResp map[string]string
	json.Unmarshal(wNonExistentAuth.Body.Bytes(), &nonExistentAuthErrResp)
	assert.Equal(t, "invalid token: user not found", nonExistentAuthErrResp["error"]) 
}
