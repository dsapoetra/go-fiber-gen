package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dsapoetra/go-fiber-gen/internal/generator"
)

func main() {
	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current directory: %v\n", err)
		os.Exit(1)
	}

	projectName := "fiber-swagger-example"
	if len(os.Args) > 1 {
		projectName = os.Args[1]
	}

	// Create new generator instance
	gen := generator.New(filepath.Join(currentDir, projectName))

	// Generate project
	if err := gen.Generate(projectName); err != nil {
		fmt.Printf("Error generating project: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Project %s created successfully!\n", projectName)
	fmt.Println("\nNext steps:")
	fmt.Println("1. cd", projectName)
	fmt.Println("2. Run 'go mod tidy' to download dependencies")
	fmt.Println("3. Update .env with your database credentials")
	fmt.Println("4. Implement the business logic in handlers")
	fmt.Println("5. Install golang-migrate: make install-migrate")
	fmt.Println("6. Update database credentials in Makefile")
	fmt.Println("7. Run migrations: make migrate-up")
}
