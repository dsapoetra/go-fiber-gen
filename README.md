
# Go Fiber Gen

Go Fiber Gen is a Go-based application leveraging the Fiber framework. It provides utilities to generate server-side components efficiently.

## Features

- Built with Go and the Fiber framework.
- Modular and scalable structure.
- Template-based generator for creating server components.

## Project Structure

```
go-fiber-gen/
├── cmd/
│   └── go-fiber-gen/
│       └── main.go         # Main entry point for the application
├── internal/
│   └── generator/
│       ├── generator.go    # Core logic for component generation
│       └── templates.go    # Templates used by the generator
├── go.mod                  # Go module file
```

## Requirements

- [Go](https://go.dev/) (version 1.20 or later recommended)
- [Fiber](https://gofiber.io/) framework

## Getting Started

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/go-fiber-gen.git
   cd go-fiber-gen
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

### Usage

Run the main application:

```bash
go install github.com/dsapoetra/go-fiber-gen/cmd/go-fiber-gen@latest
go-fiber-gen <project-name>
```

### Customization

- Modify the templates in `internal/generator/templates.go` to customize the generated components.
- Extend the logic in `internal/generator/generator.go` to add new features.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Go](https://go.dev/)
- [Fiber Framework](https://gofiber.io/)
