package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/evanw/esbuild/pkg/api"
)

var externalAssets = map[string]string{
	"react.js":     "https://unpkg.com/react@18/umd/react.production.min.js",
	"react-dom.js": "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js",
}

func main() {
	// 1. Setup Directories
	// #nosec G301 - Build script needs to create public readable asset directories
	_ = os.MkdirAll("public/assets", 0755)
	// #nosec G301 - Build script needs to create readable bin directories
	_ = os.MkdirAll("bin", 0755)

	ensureTailwind()

	// 2. Download Dependencies
	for name, url := range externalAssets {
		downloadIfMissing(filepath.Join("public/assets", name), url)
	}

	// 3. Create Proxies for ESBuild to map imports to window globals
	// #nosec G306 - Build script creates readable proxy files
	_ = os.WriteFile("ui/react-proxy.js", []byte(`
export default window.React;
export const useState = window.React.useState;
export const useEffect = window.React.useEffect;
export const useCallback = window.React.useCallback;
export const useMemo = window.React.useMemo;
export const Fragment = window.React.Fragment;
export const createElement = window.React.createElement;
`), 0644)

	// #nosec G306 - Build script creates readable proxy files
	_ = os.WriteFile("ui/react-dom-proxy.js", []byte(`
export const createRoot = window.ReactDOM.createRoot;
`), 0644)

	// 4. Bundle with ESBuild
	fmt.Println("Bundling JS with esbuild...")
	result := api.Build(api.BuildOptions{
		EntryPoints:       []string{"ui/main.jsx"},
		Bundle:            true,
		MinifyWhitespace:  true,
		MinifyIdentifiers: true,
		MinifySyntax:      true,
		Outfile:           "public/assets/app.js",
		Alias: map[string]string{
			"react":            "./ui/react-proxy.js",
			"react-dom/client": "./ui/react-dom-proxy.js",
		},
		Define: map[string]string{
			"process.env.NODE_ENV": "\"production\"",
		},
		Format: api.FormatIIFE,
		Write:  true,
	})

	if len(result.Errors) > 0 {
		for _, err := range result.Errors {
			fmt.Fprintf(os.Stderr, "esbuild error: %s\n", err.Text)
		}
		os.Exit(1)
	}

	// 5. Generate Tailwind CSS
	fmt.Println("Generating optimized CSS with Tailwind CLI...")
	twBinary := filepath.Join("bin", "tailwindcss")
	if runtime.GOOS == "windows" {
		twBinary += ".exe"
	}
	// #nosec G204 - Build script explicitly executes tailwind CLI
	cmd := exec.Command(twBinary, "-i", "ui/style.css", "-o", "public/assets/style.css", "--minify")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Tailwind build failed: %v", err)
	}

	// 6. Copy final index.html
	fmt.Println("Generating final index.html...")
	content, err := os.ReadFile("ui/index.html")
	if err != nil {
		log.Fatalf("failed to read template: %v", err)
	}

	timestamp := time.Now().Unix()
	htmlStr := string(content)
	htmlStr = strings.Replace(htmlStr, "/assets/app.js", fmt.Sprintf("/assets/app.js?v=%d", timestamp), 1)
	htmlStr = strings.Replace(htmlStr, "/assets/style.css", fmt.Sprintf("/assets/style.css?v=%d", timestamp), 1)

	// #nosec G306 G703 - Build script creates readable public index
	_ = os.WriteFile("public/index.html", []byte(htmlStr), 0644)

	// 6.5 Copy unified install script to public directory
	fmt.Println("Copying install script...")
	if scriptData, err := os.ReadFile("scripts/install.sh"); err == nil {
		// #nosec G306 G703 - Build script copies install.sh
		_ = os.WriteFile("public/install.sh", scriptData, 0644)
	} else {
		log.Fatalf("failed to read scripts/install.sh: %v", err)
	}

	// 7. Compile CLI binaries
	fmt.Println("Compiling CLI binaries for distribution...")
	targets := []struct{ OS, Arch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	}

	version := "dev"
	if out, err := exec.Command("git", "describe", "--tags", "--always", "--dirty").Output(); err == nil {
		version = strings.TrimSpace(string(out))
		version = strings.TrimPrefix(version, "v")
	}
	ldflags := fmt.Sprintf("-s -w -X main.Version=%s", version)

	// #nosec G301 - Build script creates readable binary directories
	_ = os.MkdirAll("bin/cli", 0755)
	for _, t := range targets {
		out := filepath.Join("bin/cli", fmt.Sprintf("tsm-%s-%s", t.OS, t.Arch))
		if t.OS == "windows" {
			out += ".exe"
		}

		// #nosec G204 - Build script explicitly runs go build
		cmd := exec.Command("go", "build", "-ldflags="+ldflags, "-trimpath", "-o", out, "./cmd/tsm-cli")
		cmd.Env = append(os.Environ(), "GOOS="+t.OS, "GOARCH="+t.Arch, "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("failed to build cli for %s/%s: %v", t.OS, t.Arch, err)
		}
	}
}

func downloadIfMissing(path, url string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	fmt.Printf("Downloading %s...\n", filepath.Base(path))
	// #nosec G107 - Build script is explicitly designed to download known assets
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("download failed: %v", err)
	}
	defer resp.Body.Close()
	// #nosec G304 - Build script controls the file paths being written to
	f, _ := os.Create(path)
	defer f.Close()
	_, _ = io.Copy(f, resp.Body)
}

func ensureTailwind() {
	path := filepath.Join("bin", "tailwindcss")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	if _, err := os.Stat(path); err == nil {
		return
	}

	var osName, archName string
	switch runtime.GOOS {
	case "linux":
		osName = "linux"
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	default:
		log.Fatalf("unsupported OS for tailwind download: %s", runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "amd64":
		archName = "x64"
	case "arm64":
		archName = "arm64"
	default:
		log.Fatalf("unsupported arch for tailwind download: %s", runtime.GOARCH)
	}

	binaryName := fmt.Sprintf("tailwindcss-%s-%s", osName, archName)
	if osName == "windows" {
		binaryName += ".exe"
	}

	url := fmt.Sprintf("https://github.com/tailwindlabs/tailwindcss/releases/latest/download/%s", binaryName)
	downloadIfMissing(path, url)
	// #nosec G302 - Build script intentionally makes the downloaded binary executable
	_ = os.Chmod(path, 0755)
}
