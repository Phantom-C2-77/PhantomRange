package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Phantom-C2-77/PhantomRange/internal/shop"
)

func main() {
	addr := flag.String("addr", ":8080", "Listen address")
	flag.Parse()

	fmt.Print("\033[35m")
	fmt.Println(`
   ___  __                __             ____  __
  / _ \/ /  ___ ____  ___/ /____  __ _  / __/ / /  ___  ___
 / ___/ _ \/ _ '/ _ \/ __/ __/ _ \/  ' \_\ \ / _ \/ _ \/ _ \
/_/  /_//_/\_,_/_//_/\__/\__/\___/_/_/_/___//_//_/\___/ .__/
                                                      /_/`)
	fmt.Print("\033[0m")
	fmt.Println("\n  \033[36m[::] PhantomShop — Vulnerable E-Commerce Training\033[0m")
	fmt.Println("  \033[2m[::] 22 Vulnerabilities | 10 Categories | 4,200 Points\033[0m")
	fmt.Println()
	fmt.Printf("  \033[32m[+]\033[0m Shop:         http://localhost%s\n", *addr)
	fmt.Printf("  \033[32m[+]\033[0m Vulns:        http://localhost%s/vulns\n", *addr)
	fmt.Printf("  \033[32m[+]\033[0m Scoreboard:   http://localhost%s/scoreboard\n", *addr)
	fmt.Println()
	fmt.Println("  \033[33m[!]\033[0m Intentionally vulnerable — do NOT expose to internet")
	fmt.Println()

	app := shop.New()
	if err := app.Start(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "  \033[31m[-]\033[0m Error: %v\n", err)
		os.Exit(1)
	}
}
