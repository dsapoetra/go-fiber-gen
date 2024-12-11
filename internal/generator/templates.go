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
	"your-project-name/services"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func (h *UserHandler) Register(c *fiber.Ctx) error {
	// Implementation
	return nil
}

func (h *UserHandler) Login(c *fiber.Ctx) error {
	// Implementation
	return nil
}

func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	// Implementation
	return nil
}
`

	authMiddlewareTemplate = `package middleware

import (
	"github.com/gofiber/fiber/v2"
	"your-project-name/pkg/jwt"
)

func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}

		// Validate token
		// Implementation

		return c.Next()
	}
}
`

	userModelTemplate = `package models

import "time"

type User struct {
	ID        int64     ` + "`db:\"id\" json:\"id\"`" + `
	Username  string    ` + "`db:\"username\" json:\"username\"`" + `
	Password  string    ` + "`db:\"password\" json:\"password\"`" + `
	Email     string    ` + "`db:\"email\" json:\"email\"`" + `
	CreatedAt time.Time ` + "`db:\"created_at\" json:\"created_at\"`" + `
	UpdatedAt time.Time ` + "`db:\"updated_at\" json:\"updated_at\"`" + `
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

func ValidateToken(tokenString string, secret string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
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
`

	userServiceTemplate = `package services

import (
	"your-project-name/models"
	"your-project-name/repositories"
	"your-project-name/pkg/hash"
)

type UserService struct {
	userRepo *repositories.UserRepository
}

func NewUserService(userRepo *repositories.UserRepository) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) Register(user *models.User) error {
	hashedPassword, err := hash.HashPassword(user.Password)
	if err != nil {
		return err
	}
	
	user.Password = hashedPassword
	return s.userRepo.Create(user)
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
)
