package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type Client struct {
	Id          string
	Conn        *websocket.Conn
	LoginStatus bool
}

type Payload struct {
	Action string `json:"action"`
	Type string `json:"type"`
	URL    string `json:"url"`
}

type Claims struct {
	Provider
	jwt.StandardClaims
}

// Add a new struct for Provider
type Provider struct {
	Provider string
	Id       string
	Username string
	Email    string
}

var clients []*Client

var limiters = make(map[string]*rate.Limiter)
var limitersMutex sync.Mutex

var upgrader = websocket.Upgrader{}

// Add environment variables for Google OAuth
var googleOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URI"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/auth", TokenURL: "https://oauth2.googleapis.com/token"},
}

func main() {
	err_ := godotenv.Load()
	if err_ != nil {
		logrus.Error("Error loading .env file")
	}

	initLogging()

	router := mux.NewRouter()

	// Apply the rate limiter middleware to the routes
	router.Use(rateLimiterMiddleware)

	websocketRoute := router.PathPrefix("/").Subrouter()
	websocketRoute.Use(rateLimiterMiddleware)
	websocketRoute.HandleFunc("/", handleWebSocket)

	router.HandleFunc("/auth/discord/callback", handleDiscordCallback)

	router.HandleFunc("/auth/google/callback", handleGoogleCallback)


	router.HandleFunc("/auth/discord/{cid}", handleDiscordOAuth)
	router.HandleFunc("/auth/google/{cid}", handleGoogleOAuth)

	router.HandleFunc("/success", handleSuccess)

	router.HandleFunc("/health", handleHealth)

	logrus.Info("Starting Server")
	err := http.ListenAndServe(":8080", router)
	if err != nil {
		logrus.Error("Error starting server:", err)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        logrus.Error("Error upgrading websocket connection:", err)
        return
    }

	logrus.Info("Client Connected")

	client := &Client{
		Id:   "",
		Conn: conn,
	}

	clients = append(clients, client)

	for {
		var payload Payload
		err := conn.ReadJSON(&payload)
		if err != nil {
			logrus.Error("Error reading JSON:", err)
			removeClient(client)
			return
		}

		if !client.LoginStatus {
			if payload.Action == "getLogin" {
				client.Id = uuid.New().String()
				client.LoginStatus = true
				var url string

				switch(payload.Type) {
				case "discord":
					url = fmt.Sprintf("/auth/discord/%s", client.Id)
				case "google":
					url = fmt.Sprintf("/auth/google/%s", client.Id)
				default:
					logrus.Warn("Defaulting to Discord, Unknown type of getLogin: %s", payload.Type)
					url = fmt.Sprintf("/auth/discord/%s", client.Id)
				}
				

				loginPayload := Payload{
					Action: "login_url",
					Type: payload.Type,
					URL:    fmt.Sprintf("%s%s", os.Getenv("URL_BASE"), url),
				}

				err = conn.WriteJSON(loginPayload)
				if err != nil {
					logrus.Error("Error writing JSON:", err)
					return
				}
			} else {
				logrus.Warn("Error: Client not logged in")
				return
			}
		}
	}
}

// Add a function to remove a client from the clients slice
func removeClient(clientToRemove *Client) {
	for i, client := range clients {
		if client == clientToRemove {
			client.Conn.Close()
			clients = append(clients[:i], clients[i+1:]...)
			return
		}
	}
}

// Handler for Discord OAuth login
func handleDiscordOAuth(w http.ResponseWriter, r *http.Request) {
	// Get the required environment variables
	clientId := os.Getenv("DISCORD_CLIENT_ID")
	redirectUri := os.Getenv("DISCORD_REDIRECT_URI")
	// Get the CID from the route variable
	vars := mux.Vars(r)
	cid := vars["cid"]

	// Build the Discord OAuth URL with the CID in the state parameter
	oauthUrl := fmt.Sprintf("https://discord.com/api/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=identify&state=%s", clientId, redirectUri, cid)

	// Redirect the user to the Discord OAuth URL
	http.Redirect(w, r, oauthUrl, http.StatusTemporaryRedirect)
}

func handleDiscordCallback(w http.ResponseWriter, r *http.Request) {
	// Get the authorization code from the query parameters
	code := r.URL.Query().Get("code")

	// Get the state from the query parameters
	state := r.URL.Query().Get("state")

	// Find the client that matches the state
	client := getClientByState(state)

	if client == nil {
		logrus.Error("Error: Client not found for state:", state)
		http.Error(w, "Client not found", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for an access token
	accessToken, err := exchangeCodeForToken(code)
	if err != nil {
		logrus.Error("Error exchanging code for token:", err)
		http.Error(w, "Error exchanging code for token", http.StatusInternalServerError)
		return
	}

	// Get the user information using the access token
	userInfo, err := getUserInfo("discord", accessToken)
	if err != nil {
		logrus.Error("Error getting user info:", err)
		http.Error(w, "Error getting user info", http.StatusInternalServerError)
		return
	}

	// Create a JWT with the user information
	token, err := createJwt(userInfo)
	if err != nil {
		logrus.Error("Error creating JWT:", err)
		http.Error(w, "Error creating JWT", http.StatusInternalServerError)
		return
	}

	// Send the JWT to the client over the WebSocket
	payload := Payload{
		Action: "jwt",
		Type: "discord",
		URL:    token,
	}

	err = client.Conn.WriteJSON(payload)
	if err != nil {
		logrus.Error("Error sending JWT to client:", err)
		http.Error(w, "Error sending JWT to client", http.StatusInternalServerError)
		return
	}

	removeClient(client)

	// Redirect the user to a success page
	http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
}

func getClientByState(state string) *Client {
	for _, c := range clients {
		if c.Id == state {
			return c
		}
	}
	return nil
}

// Exchange the authorization code for an access token
func exchangeCodeForToken(code string) (string, error) {
	// Get the required environment variables
	clientId := os.Getenv("DISCORD_CLIENT_ID")
	clientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	redirectUri := os.Getenv("DISCORD_REDIRECT_URI")
	data := strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s", clientId, clientSecret, code, redirectUri))

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", data)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var dataMap map[string]interface{}
	err = json.Unmarshal(body, &dataMap)
	if err != nil {
		return "", err
	}

	return dataMap["access_token"].(string), nil
}

// Create a JWT with the user information
func createJwt(claims *Claims) (string, error) {
	// Get the required environment variables
	jwtSecret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func handleSuccess(w http.ResponseWriter, r *http.Request) {
	successHTML := `
<!DOCTYPE html>
<html>
<head>
	<title>Success</title>
	<script>
		window.onload = function() {
			window.close();
		}
	</script>
</head>
<body>
	<p>Success! You may close this window.</p>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(successHTML))
}

func rateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		limitersMutex.Lock()
		limiter, exists := limiters[ip]
		if !exists {
			// Replace 50 and 5 with your desired requests per duration and burst size
			limiter = rate.NewLimiter(50, 30)
			limiters[ip] = limiter
		}
		limitersMutex.Unlock()

		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func initLogging() {
	logFile, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logrus.Error("Error opening log file:", err)
	}

	logrus.SetFormatter(&logrus.JSONFormatter{})
	mw := io.MultiWriter(os.Stdout, logFile)
	logrus.SetOutput(mw)
	logrus.SetReportCaller(true)
	logrus.SetLevel(logrus.InfoLevel)
}

func handleGoogleOAuth(w http.ResponseWriter, r *http.Request) {
	// Get the CID from the route variable
	vars := mux.Vars(r)
	cid := vars["cid"]

	// Build the Google OAuth URL with the CID in the state parameter
	oauthUrl := googleOauthConfig.AuthCodeURL(cid)

	// Redirect the user to the Google OAuth URL
	http.Redirect(w, r, oauthUrl, http.StatusTemporaryRedirect)
}

// Replace the getUserInfo function with a more generic one
func getUserInfo(provider string, accessToken string) (*Claims, error) {
	var req *http.Request
	var err error
	var userInfo Provider

	if provider == "discord" {
		req, err = http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	} else if provider == "google" {
		req, err = http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	} else {
		return nil, fmt.Errorf("unsupported provider")
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		Provider: userInfo,
	}

	return claims, nil
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Get the authorization code from the query parameters
	code := r.URL.Query().Get("code")

	// Get the state from the query parameters
	state := r.URL.Query().Get("state")

	// Find the client that matches the state
	client := getClientByState(state)

	if client == nil {
		logrus.Error("Error: Client not found for state:", state)
		http.Error(w, "Client not found", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for an access token
    token, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        logrus.Error("Error exchanging code for token:", err)
        http.Error(w, "Error exchanging code for token", http.StatusInternalServerError)
        return
    }
    accessToken := token.AccessToken

	// Get the user information using the access token
	userInfo, err := getUserInfo("google", accessToken)
	if err != nil {
		logrus.Error("Error getting user info:", err)
		http.Error(w, "Error getting user info", http.StatusInternalServerError)
		return
	}

	// Create a JWT with the user information
	jwtToken, _err := createJwt(userInfo)
	if _err != nil {
		logrus.Error("Error creating JWT:", err)
		http.Error(w, "Error creating JWT", http.StatusInternalServerError)
		return
	}

	// Send the JWT to the client over the WebSocket
	payload := Payload{
		Action: "jwt",
		Type: "google",
		URL:    jwtToken,
	}

	err = client.Conn.WriteJSON(payload)
	if err != nil {
		logrus.Error("Error sending JWT to client:", err)
		http.Error(w, "Error sending JWT to client", http.StatusInternalServerError)
		return
	}

	go removeClient(client)

	// Redirect the user to a success page
	http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
