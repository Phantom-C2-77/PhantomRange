package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Phantom-C2-77/PhantomRange/internal/webapp"
)

const banner = `
    ___  __                __               ___
   / _ \/ /  ___ ____  ___/ /____  __ _    / _ \___ ____  ___ ____
  / ___/ _ \/ _ '/ _ \/ __/ __/ _ \/  ' \  / , _/ _ '/ _ \/ _ '/ -_)
 /_/  /_//_/\_,_/_//_/\__/\__/\___/_/_/_/ /_/|_|\_,_/_//_/\_, /\__/
                                                          /___/
`

func main() {
	addr := flag.String("addr", ":8080", "Listen address")
	flag.Parse()

	fmt.Printf("\033[35m%s\033[0m", banner)
	fmt.Printf("  \033[36m[::] PhantomRange — Vulnerable Training Environment\033[0m\n")
	fmt.Printf("  \033[2m[::] Version: 1.0.0\033[0m\n\n")

	fmt.Printf("  \033[34m[*]\033[0m Starting server on %s\n", *addr)
	fmt.Printf("  \033[32m[+]\033[0m Dashboard:  http://localhost%s\n", *addr)
	fmt.Printf("  \033[32m[+]\033[0m Challenges: http://localhost%s/challenges\n", *addr)
	fmt.Printf("  \033[32m[+]\033[0m Scoreboard: http://localhost%s/scoreboard\n", *addr)
	fmt.Println()
	fmt.Printf("  \033[33m[!]\033[0m This is an intentionally vulnerable application.\n")
	fmt.Printf("  \033[33m[!]\033[0m Do NOT expose to the internet.\n\n")

	srv := webapp.New()
	if err := srv.Start(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "  \033[31m[-]\033[0m Server error: %v\n", err)
		os.Exit(1)
	}
}
