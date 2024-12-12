package generator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Generator struct {
	projectPath string
}

func New(projectPath string) *Generator {
	return &Generator{
		projectPath: projectPath,
	}
}

func (g *Generator) Generate(projectName string) error {
	// Validate project name
	if err := g.validateProjectName(projectName); err != nil {
		return err
	}

	// Create project structure
	if err := g.createDirectories(projectName); err != nil {
		return err
	}

	// Create files
	if err := g.createFiles(projectName); err != nil {
		return err
	}

	// Create migrations
	return g.createMigrations(projectName)
}

func (g *Generator) validateProjectName(name string) error {
	if name == "" {
		return errors.New("project name cannot be empty")
	}
	matched, err := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-_]*$`, name)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("invalid project name: must start with a letter and contain only letters, numbers, hyphens, or underscores")
	}
	return nil
}

func (g *Generator) createDirectories(projectName string) error {
	dirs := []string{
		"cmd/server",
		"config",
		"db",
		"db/migrations",
		"handlers",
		"middleware",
		"models",
		"pkg/hash",
		"pkg/jwt",
		"repositories",
		"services",
		"routes",
		"migrations",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(g.projectPath, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) createFiles(projectName string) error {
	files := map[string]string{
		"cmd/server/main.go":              mainTemplate,
		"config/config.go":                configTemplate,
		"db/db.go":                        dbTemplate,
		"handlers/user_handler.go":        userHandlerTemplate,
		"middleware/auth_middleware.go":   authMiddlewareTemplate,
		"models/user.go":                  userModelTemplate,
		"pkg/hash/hash.go":                hashTemplate,
		"pkg/jwt/jwt.go":                  jwtTemplate,
		"repositories/user_repository.go": userRepositoryTemplate,
		"services/user_service.go":        userServiceTemplate,
		"routes/routes.go":                routesTemplate,
		".env":                            envTemplate,
		"go.mod":                          modTemplate,
		"Makefile":                        makefileTemplate,
		"services/user_service_test.go":   userServiceTestTemplate,
		"handlers/user_handler_test.go":   userHandlerTestTemplate,
	}

	for file, content := range files {
		filePath := filepath.Join(g.projectPath, file)
		if err := g.createFile(filePath, content); err != nil {
			return err
		}
		if err := g.replaceInFile(filePath, "your-project-name", projectName); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) createMigrations(projectName string) error {
	migrationTime := time.Now().Format("20060102150405")

	upPath := filepath.Join(g.projectPath, "db/migrations",
		fmt.Sprintf("%s_create_users_table.up.sql", migrationTime))
	if err := g.createFile(upPath, initialMigrationUpTemplate); err != nil {
		return err
	}

	downPath := filepath.Join(g.projectPath, "db/migrations",
		fmt.Sprintf("%s_create_users_table.down.sql", migrationTime))
	return g.createFile(downPath, initialMigrationDownTemplate)
}

func (g *Generator) createFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func (g *Generator) replaceInFile(path, old, new string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	newContent := strings.ReplaceAll(string(content), old, new)
	return os.WriteFile(path, []byte(newContent), 0644)
}
