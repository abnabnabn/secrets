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

	"github.com/evanw/esbuild/pkg/api"
)

var externalAssets = map[string]string{
	"react.js":     "https://unpkg.com/react@18/umd/react.production.min.js",
	"react-dom.js": "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js",
}

func main() {
	// 1. Setup Directories
	os.MkdirAll("public/assets", 0755)
	os.MkdirAll("bin", 0755)

	ensureTailwind()

	// 2. Download Dependencies
	for name, url := range externalAssets {
		downloadIfMissing(filepath.Join("public/assets", name), url)
	}

	// 3. Create Proxies for ESBuild to map imports to window globals
	os.WriteFile("ui/react-proxy.js", []byte(`
export default window.React;
export const useState = window.React.useState;
export const useEffect = window.React.useEffect;
export const useCallback = window.React.useCallback;
export const useMemo = window.React.useMemo;
export const Fragment = window.React.Fragment;
export const createElement = window.React.createElement;
`), 0644)

	os.WriteFile("ui/react-dom-proxy.js", []byte(`
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
	os.WriteFile("public/index.html", content, 0644)
}

func downloadIfMissing(path, url string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	fmt.Printf("Downloading %s...\n", filepath.Base(path))
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("download failed: %v", err)
	}
	defer resp.Body.Close()
	f, _ := os.Create(path)
	defer f.Close()
	io.Copy(f, resp.Body)
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
	os.Chmod(path, 0755)
}
