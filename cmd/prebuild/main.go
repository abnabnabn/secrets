package main

import (
	"log"
	"os"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: prebuild <input> <output>")
	}

	input := os.Args[1]
	output := os.Args[2]

	content, err := os.ReadFile(input)
	if err != nil {
		log.Fatalf("failed to read input: %v", err)
	}

	m := minify.New()
	m.AddFunc("text/html", html.Minify)
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("text/javascript", js.Minify)

	// Since our index.html contains JS in <script> tags, 
	// the HTML minifier will automatically call the JS minifier for those sections.
	minified, err := m.Bytes("text/html", content)
	if err != nil {
		log.Fatalf("minification failed: %v", err)
	}

	err = os.WriteFile(output, minified, 0644)
	if err != nil {
		log.Fatalf("failed to write output: %v", err)
	}
}
