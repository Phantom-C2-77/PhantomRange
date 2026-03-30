package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Phantom-C2-77/PhantomRange/internal/shop"
)

func main() {
	addr := flag.String("addr", ":9000", "Listen address")
	flag.Parse()

	fmt.Print("\033[35m")
	fmt.Println(`
                      ___
                 ____/   \____
            ____/    _   _    \____
       ____/   _____/ \_/ \_____   \____
  ____/  _____/  PHANTOM SHOP  \_____  \____
 /______/____________________________\______\
        \___        ✦        ___/
            \_______•_______/`)
	fmt.Print("\033[0m")
	fmt.Println("\n  \033[36m[::] PhantomShop — Vulnerable E-Commerce Training\033[0m")
	fmt.Println("  \033[2m[::] 50 Vulnerabilities | 10 Categories | 8,750 Points\033[0m")
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
