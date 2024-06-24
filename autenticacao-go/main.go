package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var (
	secretKey = []byte("ChaveSecretaSuperSecreta")
	users     = map[string]struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}{}
	sessionTimeout = 15 * time.Minute 
)


type Credentials struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	Email           string `json:"email"`
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	NewUsername     string `json:"newUsername"`
}


type Claims struct {
	User string `json:"user"`
	jwt.StandardClaims
}

func main() {
	router := mux.NewRouter()

	
	fs := http.FileServer(http.Dir("./templates"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	
	router.HandleFunc("/atualizar-perfil", atualizarPerfil).Methods("POST")
	router.HandleFunc("/perfil", servePersonalizarPerfilPage).Methods("GET")
	router.HandleFunc("/login", serveLoginPage).Methods("GET")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/registro", serveRegistroPage).Methods("GET")
	router.HandleFunc("/registro", register).Methods("POST")
	router.HandleFunc("/esqueci-senha", serveEsqueciSenhaPage).Methods("GET")
	router.HandleFunc("/esqueci-senha", esqueciSenha).Methods("POST")
	router.HandleFunc("/verificar-token", serveVerificarTokenPage).Methods("GET")
	router.HandleFunc("/verificar-token", verificarToken).Methods("POST")
	router.HandleFunc("/recurso-protegido", verifySession(recursoProtegido)).Methods("GET")
	router.HandleFunc("/elemento-protegido", verifySession(elementoProtegido)).Methods("GET")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}).Methods("GET")

	fmt.Println("Servidor rodando em http://localhost:3000")
	http.ListenAndServe(":3000", router)
}

func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/login.html")
}

func serveRegistroPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/registro.html")
}

func serveEsqueciSenhaPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/esqueci_senha.html")
}

func servePersonalizarPerfilPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/personalizar_perfil.html")
}

func register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erro ao ler as credenciais", http.StatusBadRequest)
		return
	}

	
	if _, exists := users[creds.Username]; exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Usuário já existe"})
		return
	}

	
	users[creds.Username] = struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}{Password: creds.Password, Email: creds.Email} 

	
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Usuário registrado com sucesso"})
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erro ao ler as credenciais", http.StatusBadRequest)
		return
	}

	
	user, exists := users[creds.Username]
	if !exists || creds.Password != user.Password {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Credenciais inválidas"})
		return
	}

	
	token := generateRandomToken(5)
	fmt.Printf("Token de autenticação enviado para %s: %s\n", user.Email, token)

	
	http.SetCookie(w, &http.Cookie{
		Name:    "auth_token",
		Value:   token,
		Expires: time.Now().Add(5 * time.Minute), 
		Path:    "/",
	})

	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Token de autenticação enviado para seu email"})
}

func generateRandomToken(length int) string {
	const charset = "0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	token := make([]byte, length)
	for i := range token {
		token[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(token)
}

func esqueciSenha(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erro ao ler as credenciais", http.StatusBadRequest)
		return
	}

	
	var username string
	emailFound := false
	for user, info := range users {
		if info.Email == creds.Email {
			username = user
			emailFound = true
			break
		}
	}

	if !emailFound {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Email não encontrado"})
		return
	}

	
	resetToken := generateResetToken()

	
	fmt.Printf("Token de redefinição gerado para %s (%s): %s\n", username, creds.Email, resetToken)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token de redefinição enviado com sucesso"})
}

func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(sessionTimeout)
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

func generateResetToken() string {
	
	return generateRandomToken(5)
}

func recursoProtegido(w http.ResponseWriter, r *http.Request) {
	
	user := "Usuário Teste"

	
	tmpl, err := template.ParseFiles("templates/recurso_protegido.html")
	if err != nil {
		http.Error(w, "Erro ao carregar template", http.StatusInternalServerError)
		return
	}

	
	data := struct {
		Username string
	}{
		Username: user,
	}

	
	w.Header().Set("Content-Type", "text/html")
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Erro ao renderizar template", http.StatusInternalServerError)
	}
}

func elementoProtegido(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*Claims).User
	fmt.Printf("Usuário acessando elemento protegido: %s\n", user)
	
	http.Redirect(w, r, "https://loldle.net/", http.StatusSeeOther)
}

func verifySession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		
		tokenString := cookie.Value
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			http.Error(w, "Erro ao obter claims do token", http.StatusInternalServerError)
			return
		}

		
		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func atualizarPerfil(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		CurrentUsername string `json:"currentUsername"`
		CurrentPassword string `json:"currentPassword"`
		NewUsername     string `json:"newUsername"`
		NewPassword     string `json:"newPassword"`
	}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erro ao ler as credenciais", http.StatusBadRequest)
		return
	}

	
	user, exists := users[creds.CurrentUsername]
	if !exists || creds.CurrentPassword != user.Password {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Credenciais inválidas"})
		return
	}

	
	if _, exists := users[creds.NewUsername]; exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Novo nome de usuário já existe"})
		return
	}

	
	if creds.NewUsername != "" {
		
		users[creds.NewUsername] = users[creds.CurrentUsername]
		delete(users, creds.CurrentUsername)
	}

	if creds.NewPassword != "" {
		
		user.Password = creds.NewPassword
		users[creds.NewUsername] = user
	}

	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Perfil atualizado com sucesso"})
}

func serveVerificarTokenPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/verificar_token.html")
}

func verificarToken(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Erro ao ler as credenciais", http.StatusBadRequest)
		return
	}

	
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value != creds.Token {
		http.Error(w, "Token inválido ou expirado", http.StatusUnauthorized)
		return
	}

	
	sessionToken, err := generateToken(creds.Username)
	if err != nil {
		http.Error(w, "Erro ao gerar token JWT", http.StatusInternalServerError)
		return
	}

	
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(sessionTimeout),
		Path:    "/",
	})

	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token verificado com sucesso"})
}
