package generator

// Template contents for different files
const (
	mainTemplate = `package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
	"your-project-name/config"
	"your-project-name/db"
	"your-project-name/handlers"
	"your-project-name/repositories"
	"your-project-name/routes"
	"your-project-name/services"
)

func main() {
	// Load config
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	database, err := db.Connect(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Initialize repositories
	userRepo := repositories.NewUserRepository(database)

	// Initialize services
	userService := services.NewUserService(userRepo)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)

	// Initialize Fiber app
	app := fiber.New()

	// Setup routes
	routes.SetupRoutes(app, userHandler)

	// Setup Swagger
	app.Get("/swagger/*", swagger.HandlerDefault)

	// Start server
	log.Fatal(app.Listen(":3000"))
}
`

	configTemplate = `package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	JWTSecret  string
}

func LoadConfig() (config Config, err error) {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()
	
	err = viper.ReadInConfig()
	if err != nil {
		return
	}
	
	err = viper.Unmarshal(&config)
	return
}
`

	dbTemplate = `package db

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func Connect(host, port, user, password, dbname string) (*sqlx.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	
	return sqlx.Connect("postgres", dsn)
}
`

	userHandlerTemplate = `package handlers

import (
    "github.com/gofiber/fiber/v2"
    "your-project-name/models"
    "your-project-name/services"
)

type UserHandler struct {
    userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
    return &UserHandler{userService: userService}
}

func (h *UserHandler) Register(c *fiber.Ctx) error {
    var user models.User
    if err := c.BodyParser(&user); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    if err := h.userService.Register(&user); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    // Clear password before sending response
    user.Password = ""
    return c.Status(fiber.StatusCreated).JSON(user)
}

func (h *UserHandler) Login(c *fiber.Ctx) error {
    var loginRequest struct {
        Username string ` + "`json:\"username\"`" + `
        Password string ` + "`json:\"password\"`" + `
    }

    if err := c.BodyParser(&loginRequest); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    token, err := h.userService.Login(loginRequest.Username, loginRequest.Password)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid credentials",
        })
    }

    return c.JSON(fiber.Map{
        "token": token,
    })
}

func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
    userId := c.Locals("userId").(int64)
    
    user, err := h.userService.GetUserById(userId)
    if err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "User not found",
        })
    }

    // Clear password before sending response
    user.Password = ""
    return c.JSON(user)
}

// Additional example handlers...
func (h *UserHandler) ExampleCreate(c *fiber.Ctx) error {
    var item models.Example
    if err := c.BodyParser(&item); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    // Example service call
    if err := h.userService.Create(&item); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to create item",
        })
    }

    return c.Status(fiber.StatusCreated).JSON(item)
}

func (h *UserHandler) ExampleList(c *fiber.Ctx) error {
    limit := c.QueryInt("limit", 10)
    offset := c.QueryInt("offset", 0)
    
    // Example service call
    items, err := h.userService.List(limit, offset)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to retrieve items",
        })
    }

    return c.JSON(fiber.Map{
        "items": items,
        "metadata": fiber.Map{
            "limit":  limit,
            "offset": offset,
        },
    })
}
`

	authMiddlewareTemplate = `package middleware

import (
	"github.com/gofiber/fiber/v2"
	"strings"
	"your-project-name/pkg/jwt"
)

func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Authorization header required"})
		}

		// Check if the header starts with "Bearer "
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid authorization header format"})
		}

		token := parts[1]
		
		// Validate token
		claims, err := jwt.ValidateToken(token, "your-secret-key") // TODO: Use config for secret
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
		}

		// Set user ID in context
		userId := claims["user_id"].(float64)
		c.Locals("userId", int64(userId))

		return c.Next()
	}
}
`

	hashTemplate = `package hash

import (
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
`

	jwtTemplate = `package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func GenerateToken(userId uint, secret string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userId
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	return token.SignedString([]byte(secret))
}

func ValidateToken(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}
`

	userRepositoryTemplate = `package repositories

import (
	"github.com/jmoiron/sqlx"
	"your-project-name/models"
)

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	query := ` + "`" + `
		INSERT INTO users (username, email, password, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id, created_at, updated_at
	` + "`" + `
	
	return r.db.QueryRowx(query, 
		user.Username, 
		user.Email, 
		user.Password,
	).StructScan(user)
}

func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Get(&user, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindById(id int64) (*models.User, error) {
	var user models.User
	err := r.db.Get(&user, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
`

	routesTemplate = `package routes

import (
	"github.com/gofiber/fiber/v2"
	"your-project-name/handlers"
	"your-project-name/middleware"
)

func SetupRoutes(app *fiber.App, userHandler *handlers.UserHandler) {
	api := app.Group("/api")
	
	// Public routes
	auth := api.Group("/auth")
	auth.Post("/register", userHandler.Register)
	auth.Post("/login", userHandler.Login)
	
	// Protected routes
	user := api.Group("/user", middleware.AuthMiddleware())
	user.Get("/profile", userHandler.GetProfile)
}
`

	envTemplate = `DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=mydb
JWT_SECRET=your-secret-key
`

	modTemplate = `module your-project-name

go 1.21

require (
	github.com/gofiber/fiber/v2 v2.52.0
	github.com/gofiber/swagger v0.1.14
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/spf13/viper v1.18.2
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.9
	golang.org/x/crypto v0.19.0
)
`

	makefileTemplate = `# Database credentials
DB_HOST ?= localhost
DB_PORT ?= 5432
DB_USER ?= postgres
DB_PASSWORD ?= password
DB_NAME ?= mydb

# Database URL for migrations
DB_URL = postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable

.PHONY: migrate-create migrate-up migrate-down migrate-force

# Create a new migration file
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir db/migrations -seq $$name

# Run all migrations
migrate-up:
	migrate -path db/migrations -database "${DB_URL}" up

# Rollback all migrations
migrate-down:
	migrate -path db/migrations -database "${DB_URL}" down

# Force set migration version
migrate-force:
	@read -p "Enter version: " version; \
	migrate -path db/migrations -database "${DB_URL}" force $$version

# Create initial migration
create-users-migration:
	migrate create -ext sql -dir db/migrations -seq create_users_table

# Install golang-migrate
install-migrate:
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Help
help:
	@echo "Available commands:"
	@echo "  make migrate-create    - Create a new migration file"
	@echo "  make migrate-up        - Run all migrations"
	@echo "  make migrate-down      - Rollback all migrations"
	@echo "  make migrate-force     - Force set migration version"
	@echo "  make install-migrate   - Install golang-migrate tool"
`

	initialMigrationUpTemplate = `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`

	initialMigrationDownTemplate = `DROP TABLE IF EXISTS users;`

	userServiceTestTemplate = `package services

	import (
		"testing"
		"errors"
		"github.com/stretchr/testify/assert"
		"github.com/stretchr/testify/mock"
		"your-project-name/models"
	)
	
	// MockUserRepository is a mock type for the UserRepository
	type MockUserRepository struct {
		mock.Mock
	}
	
	func (m *MockUserRepository) Create(user *models.User) error {
		args := m.Called(user)
		return args.Error(0)
	}
	
	func (m *MockUserRepository) FindByUsername(username string) (*models.User, error) {
		args := m.Called(username)
		if args.Get(0) == nil {
			return nil, args.Error(1)
		}
		return args.Get(0).(*models.User), args.Error(1)
	}
	
	func (m *MockUserRepository) FindByEmail(email string) (*models.User, error) {
		args := m.Called(email)
		if args.Get(0) == nil {
			return nil, args.Error(1)
		}
		return args.Get(0).(*models.User), args.Error(1)
	}
	
	func (m *MockUserRepository) FindById(id int64) (*models.User, error) {
		args := m.Called(id)
		if args.Get(0) == nil {
			return nil, args.Error(1)
		}
		return args.Get(0).(*models.User), args.Error(1)
	}
	
	func TestUserService_Register(t *testing.T) {
		mockRepo := new(MockUserRepository)
		service := NewUserService(mockRepo)
	
		tests := []struct {
			name          string
			user          *models.User
			setupMocks    func()
			expectedError error
		}{
			{
				name: "Successful registration",
				user: &models.User{
					Username: "testuser",
					Email:    "test@example.com",
					Password: "password123",
				},
				setupMocks: func() {
					mockRepo.On("FindByUsername", "testuser").Return(nil, errors.New("not found"))
					mockRepo.On("FindByEmail", "test@example.com").Return(nil, errors.New("not found"))
					mockRepo.On("Create", mock.AnythingOfType("*models.User")).Return(nil)
				},
				expectedError: nil,
			},
			{
				name: "Username already exists",
				user: &models.User{
					Username: "existinguser",
					Email:    "test@example.com",
					Password: "password123",
				},
				setupMocks: func() {
					mockRepo.On("FindByUsername", "existinguser").Return(&models.User{}, nil)
				},
				expectedError: errors.New("username already exists"),
			},
		}
	
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockRepo.ExpectedCalls = nil
				mockRepo.Calls = nil
				tt.setupMocks()
	
				err := service.Register(tt.user)
	
				if tt.expectedError != nil {
					assert.EqualError(t, err, tt.expectedError.Error())
				} else {
					assert.NoError(t, err)
				}
				mockRepo.AssertExpectations(t)
			})
		}
	}
	
	func TestUserService_Login(t *testing.T) {
		mockRepo := new(MockUserRepository)
		service := NewUserService(mockRepo)
	
		tests := []struct {
			name          string
			username      string
			password      string
			setupMocks    func()
			expectedToken string
			expectedError error
		}{
			{
				name:     "Successful login",
				username: "testuser",
				password: "password123",
				setupMocks: func() {
					hashedPassword, _ := hash.HashPassword("password123")
					mockRepo.On("FindByUsername", "testuser").Return(&models.User{
						ID:       1,
						Username: "testuser",
						Password: hashedPassword,
					}, nil)
				},
				expectedError: nil,
			},
			{
				name:     "Invalid credentials",
				username: "testuser",
				password: "wrongpassword",
				setupMocks: func() {
					hashedPassword, _ := hash.HashPassword("password123")
					mockRepo.On("FindByUsername", "testuser").Return(&models.User{
						Username: "testuser",
						Password: hashedPassword,
					}, nil)
				},
				expectedError: errors.New("invalid credentials"),
			},
		}
	
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockRepo.ExpectedCalls = nil
				mockRepo.Calls = nil
				tt.setupMocks()
	
				token, err := service.Login(tt.username, tt.password)
	
				if tt.expectedError != nil {
					assert.EqualError(t, err, tt.expectedError.Error())
					assert.Empty(t, token)
				} else {
					assert.NoError(t, err)
					assert.NotEmpty(t, token)
				}
				mockRepo.AssertExpectations(t)
			})
		}
	}
	`

	handlerTemplate = `package handlers

import (
    "{{.ModuleName}}/models"
    "{{.ModuleName}}/services"
    "github.com/gofiber/fiber/v2"
)

type {{.Name}}Handler struct {
    {{.LowerName}}Service services.{{.Name}}ServiceInterface
}

func New{{.Name}}Handler({{.LowerName}}Service services.{{.Name}}ServiceInterface) {{.Name}}HandlerInterface {
    return &{{.Name}}Handler{ {{.LowerName}}Service: {{.LowerName}}Service }
}

type {{.Name}}HandlerInterface interface {
    Register(c *fiber.Ctx) error
    Login(c *fiber.Ctx) error
    GetProfile(c *fiber.Ctx) error
}

func (h *{{.Name}}Handler) Register(c *fiber.Ctx) error {
    var user models.{{.Name}}
    if err := c.BodyParser(&user); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    if err := h.{{.LowerName}}Service.Register(&user); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    // Clear password before sending response
    user.Password = ""
    return c.Status(fiber.StatusCreated).JSON(user)
}

func (h *{{.Name}}Handler) Login(c *fiber.Ctx) error {
    var loginRequest struct {
        Username string ` + "`json:\"username\"`" + `
        Password string ` + "`json:\"password\"`" + `
    }

    if err := c.BodyParser(&loginRequest); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    token, err := h.{{.LowerName}}Service.Login(loginRequest.Username, loginRequest.Password)
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid credentials",
        })
    }

    return c.JSON(fiber.Map{
        "token": token,
    })
}

func (h *{{.Name}}Handler) GetProfile(c *fiber.Ctx) error {
    userId := c.Locals("userId").(int64)

    user, err := h.{{.LowerName}}Service.GetUserById(userId)
    if err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error": "User not found",
        })
    }

    // Clear password before sending response
    user.Password = ""
    return c.JSON(user)
}
`

	userHandlerTestTemplate = `package handlers

import (
    "{{.ModuleName}}/models"
    "bytes"
    "encoding/json"
    "io/ioutil"
    "net/http/httptest"
    "testing"

    "github.com/gofiber/fiber/v2"
    "github.com/stretchr/testify/assert"
)

func Test{{.Name}}Handler_Register(t *testing.T) {
    tests := []struct {
        name           string
        requestBody    interface{}
        expectedStatus int
        expectedBody   string
    }{
        {
            name: "Successful registration",
            requestBody: map[string]string{
                "username": "testuser",
                "email":    "test@example.com",
                "password": "password123",
            },
            expectedStatus: fiber.StatusCreated,
            expectedBody:   ` + "`" + `{"created_at":"0001-01-01T00:00:00Z","email":"test@example.com","id":0,"password":"","updated_at":"0001-01-01T00:00:00Z","username":"testuser"}` + "`" + `,
        },
        {
            name:        "Invalid request body",
            requestBody: "invalid json",
            expectedStatus: fiber.StatusBadRequest,
            expectedBody:   ` + "`" + `{"error":"Invalid request body"}` + "`" + `,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            app := fiber.New()
            
            var body []byte
            var err error
            
            switch v := tt.requestBody.(type) {
            case string:
                body = []byte(v)
            default:
                body, err = json.Marshal(tt.requestBody)
                if err != nil {
                    t.Fatal(err)
                }
            }

            req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
            req.Header.Set("Content-Type", "application/json")

            resp, _ := app.Test(req)

            assert.Equal(t, tt.expectedStatus, resp.StatusCode)

            respBody, _ := ioutil.ReadAll(resp.Body)
            assert.JSONEq(t, tt.expectedBody, string(respBody))
        })
    }
}
`

	userServiceTemplate = `package services

import (
    "{{.ModuleName}}/models"
    "{{.ModuleName}}/repositories"
)

type {{.Name}}Service struct {
    repo repositories.{{.Name}}RepositoryInterface
}

func New{{.Name}}Service(repo repositories.{{.Name}}RepositoryInterface) {{.Name}}ServiceInterface {
    return &{{.Name}}Service{repo: repo}
}

type {{.Name}}ServiceInterface interface {
    Register(user *models.{{.Name}}) error
    Login(username, password string) (string, error)
    GetUserById(id int64) (*models.{{.Name}}, error)
}

func (s *{{.Name}}Service) Register(user *models.{{.Name}}) error {
    return s.repo.Create(user)
}

func (s *{{.Name}}Service) Login(username, password string) (string, error) {
    user, err := s.repo.GetByUsername(username)
    if err != nil {
        return "", err
    }

    // TODO: Implement password verification
    return "jwt-token", nil
}

func (s *{{.Name}}Service) GetUserById(id int64) (*models.{{.Name}}, error) {
    return s.repo.Get(id)
}
`

	userModelTemplate = `package models

import (
    "time"
)

type {{.Name}} struct {
    ID        int64     ` + "`json:\"id\"`" + `
    Username  string    ` + "`json:\"username\"`" + `
    Email     string    ` + "`json:\"email\"`" + `
    Password  string    ` + "`json:\"password\"`" + `
    CreatedAt time.Time ` + "`json:\"created_at\"`" + `
    UpdatedAt time.Time ` + "`json:\"updated_at\"`" + `
}
`
)
