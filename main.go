package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	IsActive bool   `json:"isActive"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type JWTClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	users     = make(map[int]User)
	usersBy   = make(map[string]int)
	mutex     sync.RWMutex
	nextID    = 1
	jwtSecret = []byte("your-secret-key")
)

func main() {
	http.HandleFunc("/api/auth/register", registerHandler)
	http.HandleFunc("/api/auth/login", loginHandler)
	http.HandleFunc("/api/auth/refresh", refreshHandler)
	http.HandleFunc("/api/auth/logout", logoutHandler)
	http.HandleFunc("/api/auth/me", authMiddleware(meHandler))

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID int) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-User-ID", strconv.Itoa(claims.UserID))
		next(w, r)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, `{"error": "Username, email and password are required"}`, http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	if _, exists := usersBy[req.Username]; exists {
		http.Error(w, `{"error": "Username already exists"}`, http.StatusConflict)
		return
	}

	if _, exists := usersBy[req.Email]; exists {
		http.Error(w, `{"error": "Email already exists"}`, http.StatusConflict)
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error": "Error hashing password"}`, http.StatusInternalServerError)
		return
	}

	user := User{
		ID:       nextID,
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		IsActive: true,
	}

	users[nextID] = user
	usersBy[req.Username] = nextID
	usersBy[req.Email] = nextID
	nextID++

	token, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token: token,
		User:  user,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if (req.Username == "" && req.Email == "") || req.Password == "" {
		http.Error(w, `{"error": "Username/email and password are required"}`, http.StatusBadRequest)
		return
	}

	mutex.RLock()
	defer mutex.RUnlock()

	var userID int
	var exists bool

	if req.Username != "" {
		userID, exists = usersBy[req.Username]
	} else {
		userID, exists = usersBy[req.Email]
	}

	if !exists {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	user, exists := users[userID]
	if !exists || !user.IsActive {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if !checkPasswordHash(req.Password, user.Password) {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token: token,
		User:  user,
	})
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
		return
	}

	mutex.RLock()
	user, exists := users[claims.UserID]
	mutex.RUnlock()

	if !exists || !user.IsActive {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	newToken, err := generateToken(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Token: newToken,
		User:  user,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("X-User-ID"))

	mutex.RLock()
	user, exists := users[userID]
	mutex.RUnlock()

	if !exists {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
