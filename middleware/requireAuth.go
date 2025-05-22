package middleware

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go-jwt.com/initializers"
	"go-jwt.com/models"
)

func RequireAuth(c *gin.Context) {
	// get the cookie off req
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization token"})
		return
	}

	// Decode/validate it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
	
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		if validationErr, ok := err.(*jwt.ValidationError); ok {
			if validationErr.Errors&jwt.ValidationErrorExpired != 0 {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
				return
			}
		}
		// For any other parsing errors or validation errors not specifically handled (e.g. malformed token)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	
	// If err is nil, token parsing and signature validation were successful.
	// Now, we ensure the claims are as expected and the token is marked as Valid by the library.
	// The .Valid flag is set to true if all standard claims (like exp, nbf, iat) are fine.
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Find the user with token subject.
		// The "exp" check here is technically redundant if token.Valid correctly incorporates expiration,
		// but kept as a strong explicit safeguard. If token.Valid is false due to expiry,
		// it would have been caught by the err != nil block above.
		// This means if we reach here and token.Valid is true, exp should be fine.
		// However, if token.Valid is false for some other reason not caught by err, the else below handles it.
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token: user not found"})
			return
		}

		// Attach to req 
		c.Set("user", user)

		// Continue

		c.Next()

	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
	}
}