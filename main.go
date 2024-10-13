package main

import (
    "database/sql"
    "encoding/json"
    "html/template"
    "log"
    "net/http"

    _ "github.com/go-sql-driver/mysql"
    "github.com/gorilla/sessions"
    "golang.org/x/crypto/bcrypt"
)

const (
    sessionName     = "session-name"
    adminRole       = "admin"
    userRole        = "user"
    sessionDuration = 3600
    defaultSessionKey = "your-secret-key-here-make-it-long-and-random"
)

var (
    store *sessions.CookieStore
    db    *sql.DB
)

type User struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    FullName string `json:"full_name"`
    Role     string `json:"role"`
}


func main() {
    store = sessions.NewCookieStore([]byte(defaultSessionKey))

    var err error
    db, err = sql.Open("mysql", "sql12737518:xI8TlfbZkK@tcp(sql12.freesqldatabase.com:3306)/sql12737518")
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()

    if err = db.Ping(); err != nil {
        log.Fatal("Failed to ping database:", err)
    }

    log.Println("Connected to database successfully!")

    setupRoutes()

    log.Println("Server started at http://localhost:8080/")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupRoutes() {
    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/user", userHandler)
    http.HandleFunc("/change-password", changePasswordHandler)
    http.HandleFunc("/admin", adminHandler)
    http.HandleFunc("/admin/users", adminUsersHandler)
    http.HandleFunc("/admin/delete", adminDeleteHandler)
    http.HandleFunc("/admin/change-role", adminChangeRoleHandler)
    http.HandleFunc("/admin/change-user-password", adminChangeUserPasswordHandler)

    fs := http.FileServer(http.Dir("./static"))
    http.Handle("/", http.StripPrefix("/", fs))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")
    fullName := r.FormValue("full_name")
    email := r.FormValue("email")

    if username == "" || password == "" || fullName == "" || email == "" {
        w.Header().Set("Content-Type", "application/json")
        http.Error(w, `{"error": "All fields are required"}`, http.StatusBadRequest)
        return
    }
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        log.Println("Error hashing password:", err)
        w.Header().Set("Content-Type", "application/json")
        http.Error(w, `{"error": "Internal server error"}`, http.StatusInternalServerError)
        return
    }
    _, err = db.Exec("INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)", username, hashedPassword, fullName, email)
    if err != nil {
        log.Println("Error creating user:", err)
        w.Header().Set("Content-Type", "application/json")
        http.Error(w, `{"error": "Internal server error"}`, http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"message": "Registration completed successfully!"}`))
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    var hashedPassword string
    var role string
    err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&hashedPassword, &role)

    if err != nil {
        if err == sql.ErrNoRows {
            http.Redirect(w, r, "/login.html?error=Invalid credentials", http.StatusFound)
        } else {
            log.Println("Database error:", err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
        }
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        http.Redirect(w, r, "/login.html?error=Invalid credentials", http.StatusFound)
        return
    }

    session, err := store.Get(r, sessionName)
    if err != nil {
        log.Println("Error getting session:", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    session.Values["authenticated"] = true
    session.Values["username"] = username
    session.Values["role"] = role
    session.Options.Secure = false
    session.Options.MaxAge = sessionDuration
    session.Options.SameSite = http.SameSiteLaxMode

    if err := session.Save(r, w); err != nil {
        log.Println("Error saving session:", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    log.Printf("User %s logged in successfully\n", username)

    if role == adminRole {
        http.Redirect(w, r, "/admin.html", http.StatusFound)
    } else {
        http.Redirect(w, r, "/user.html", http.StatusFound)
    }
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, sessionName)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    session.Values = make(map[interface{}]interface{})
    session.Options.MaxAge = -1 

    if err := session.Save(r, w); err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    http.Redirect(w, r, "/login.html?message=Logged out successfully", http.StatusFound)
}


func userHandler(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, sessionName)
    if err != nil || session.Values["authenticated"] == nil {
        log.Println("User is not authenticated, redirecting to login")
        http.Redirect(w, r, "/login.html", http.StatusFound)
        return
    }

    username, ok := session.Values["username"].(string)
    if !ok {
        log.Println("Failed to get username from session, redirecting to login")
        http.Redirect(w, r, "/login.html", http.StatusFound)
        return
    }

    var user User
    err = db.QueryRow("SELECT username, email, full_name, role FROM users WHERE username = ?", username).
        Scan(&user.Username, &user.Email, &user.FullName, &user.Role)
    if err != nil {
        log.Println("Failed to fetch user profile:", err)
        http.Error(w, "Failed to fetch user profile", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(user); err != nil {
        log.Println("Failed to encode user profile to JSON:", err)
        http.Error(w, "Failed to encode user profile to JSON", http.StatusInternalServerError)
        return
    }
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    session, err := store.Get(r, sessionName)
    if err != nil || session.Values["authenticated"] == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    username := session.Values["username"].(string)
    var req struct {
        CurrentPassword string `json:"current_password"`
        NewPassword     string `json:"new_password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    var hashedPassword string
    err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.CurrentPassword)); err != nil {
        http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
        return
    }
    newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing new password", http.StatusInternalServerError)
        return
    }
    _, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", newHashedPassword, username)
    if err != nil {
        http.Error(w, "Failed to update password", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}


func checkAdminSession(w http.ResponseWriter, r *http.Request) bool {
    session, err := store.Get(r, sessionName)
    if err != nil {
        log.Println("Error getting session:", err)
        http.Redirect(w, r, "/login.html?error=Session error", http.StatusFound)
        return false
    }
    role, ok := session.Values["role"].(string)
    if !ok || role != adminRole {
        http.Redirect(w, r, "/login.html?error=Unauthorized access", http.StatusFound)
        return false
    }
    return true
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    if !checkAdminSession(w, r) {
        return
    }

    if r.Method == http.MethodPost {
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Failed to parse form", http.StatusBadRequest)
            return
        }

        username := r.FormValue("username")
        password := r.FormValue("password")
        fullName := r.FormValue("full_name")
        email := r.FormValue("email")

        if username == "" || password == "" || fullName == "" || email == "" {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(map[string]string{"error": "All fields are required"})
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            log.Println("Error hashing password:", err)
            http.Error(w, "Error hashing password", http.StatusInternalServerError)
            return
        }

        _, err = db.Exec("INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)", 
                         username, hashedPassword, fullName, email, userRole)
        if err != nil {
            log.Println("Error creating user:", err)
            http.Error(w, "Error creating user", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "User added successfully"})
        return
    }

    tmpl, err := template.ParseFiles("./static/admin.html")
    if err != nil {
        log.Println("Failed to load template:", err)
        http.Error(w, "Failed to load template", http.StatusInternalServerError)
        return
    }

    if err := tmpl.Execute(w, nil); err != nil {
        log.Println("Failed to execute template:", err)
        http.Error(w, "Failed to render admin page", http.StatusInternalServerError)
        return
    }
}

func adminUsersHandler(w http.ResponseWriter, r *http.Request) {
    if !checkAdminSession(w, r) {
        return
    }
    session, _ := store.Get(r, sessionName)
    loggedInUsername, _ := session.Values["username"].(string)
    rows, err := db.Query("SELECT username, full_name, email, role FROM users WHERE username != ?", loggedInUsername)
    if err != nil {
        log.Println("Failed to fetch users:", err)
        http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    var users []User
    for rows.Next() {
        var user User
        if err := rows.Scan(&user.Username, &user.FullName, &user.Email, &user.Role); err != nil {
            log.Println("Failed to scan user:", err)
            http.Error(w, "Failed to scan user", http.StatusInternalServerError)
            return
        }
        users = append(users, user)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}


func adminDeleteHandler(w http.ResponseWriter, r *http.Request) {
    if !checkAdminSession(w, r) {
        return
    }

    username := r.URL.Query().Get("username")
    if username == "" {
        http.Error(w, "Username is required", http.StatusBadRequest)
        return
    }

    _, err := db.Exec("DELETE FROM users WHERE username = ?", username)
    if err != nil {
        log.Println("Failed to delete user:", err)
        http.Error(w, "Failed to delete user", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

func adminChangeRoleHandler(w http.ResponseWriter, r *http.Request) {
    if !checkAdminSession(w, r) {
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    username := r.FormValue("username")
    newRole := r.FormValue("role")
    if username == "" || newRole == "" {
        http.Error(w, "Username and role are required", http.StatusBadRequest)
        return
    }
    _, err := db.Exec("UPDATE users SET role = ? WHERE username = ?", newRole, username)
    if err != nil {
        log.Println("Failed to change user role:", err)
        http.Error(w, "Failed to change user role", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "User role updated successfully"})
}

func adminChangeUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
    if !checkAdminSession(w, r) {
        return
    }

    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    newPassword := r.FormValue("new_password")

    if username == "" || newPassword == "" {
        http.Error(w, "Username and new password are required", http.StatusBadRequest)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        log.Println("Error hashing new password:", err)
        http.Error(w, "Error hashing new password", http.StatusInternalServerError)
        return
    }

    _, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
    if err != nil {
        log.Println("Failed to update user password:", err)
        http.Error(w, "Failed to update user password", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
}