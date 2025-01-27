package server

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"my-kms/internal/auth"
)

// Authenticate is a middleware that authenticates the request using Firebase and sets the user's identity in context.
func (s *Server) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// 2. Expect the header to be in the format "Bearer <token>"
		var token string
		_, err := fmt.Sscanf(authHeader, "Bearer %s", &token)
		if err != nil || token == "" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// 3. Verify the ID token with Firebase
		ctx := context.Background()
		decodedToken, err := s.FirebaseAuth.VerifyIDToken(ctx, token)
		if err != nil {
			log.Printf("Failed to verify ID token: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 4. Retrieve the user's role from MongoDB using firebaseUID
		firebaseUID := decodedToken.UID
		user, err := s.MongoUserStore.GetUserByFirebaseUID(ctx, firebaseUID)
		if err != nil {
			log.Printf("Failed to retrieve user from MongoDB: %v", err)
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// 5. Create an Identity object
		identity := auth.Identity{
			Name: firebaseUID, // Using Firebase UID as the name
			Role: auth.Role(user.Role),
			// Optionally, add FirebaseUID if the Identity struct includes it
			// FirebaseUID: firebaseUID,
		}

		// 6. Inject the Identity into the request context
		ctx = context.WithValue(r.Context(), "identity", identity)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}
