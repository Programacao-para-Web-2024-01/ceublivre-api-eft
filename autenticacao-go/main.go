package main

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"

	"html/template"
	"log"

	"github.com/gorilla/mux"
)

var secretKey = []byte("ChaveSecretaSuperSecreta")

// Credentials representa as credenciais de login
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims representa os claims do token JWT
type Claims struct {
	User string `json:"user"`
	jwt.StandardClaims
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", serveLoginPage).Methods("GET") // Rota para a página de login
	router.HandleFunc("/login", login).Methods("POST")         // Rota para autenticação
	router.HandleFunc("/recurso-protegido", verifyToken(recursoProtegido)).Methods("GET")
	router.HandleFunc("/elemento-protegido", verifyToken(elementoProtegido)).Methods("GET")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}).Methods("GET")

	// Arquivos estáticos
	fs := http.FileServer(http.Dir("templates"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	log.Println("Servidor rodando em http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", router))
}

func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Verificar credenciais
	if creds.Username == "usuario" && creds.Password == "senha" {
		tokenString, err := generateToken(creds.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Credenciais inválidas"})
	}
}

func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		User: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func recursoProtegido(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*Claims).User
	response := map[string]string{"message": "Você acessou o recurso protegido!", "user": user}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func elementoProtegido(w http.ResponseWriter, r *http.Request) {
	// Verificar se o token é válido
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		// Redirecionar para https://onesquareminesweeper.com/ se o token não for fornecido
		http.Redirect(w, r, "https://onesquareminesweeper.com/", http.StatusSeeOther)
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		// Redirecionar para https://onesquareminesweeper.com/ se o token for inválido
		http.Redirect(w, r, "https://onesquareminesweeper.com/", http.StatusSeeOther)
		return
	}

	// Token é válido, redirecionar para https://loldle.net/
	http.Redirect(w, r, "https://loldle.net/", http.StatusSeeOther)
}

func verifyToken(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")

		if tokenString == "" {
			// Redirecionar para https://onesquareminesweeper.com/ se o token não for fornecido
			http.Redirect(w, r, "https://onesquareminesweeper.com/", http.StatusSeeOther)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			// Redirecionar para https://onesquareminesweeper.com/ se o token for inválido
			http.Redirect(w, r, "https://onesquareminesweeper.com/", http.StatusSeeOther)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Erro ao obter claims do token"})
			return
		}

		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
