package shop

import (
	"net/http"

	"github.com/phantom-offensive/PhantomRange/internal/db"
)

// App is the main PhantomShop application.
type App struct {
	mux *http.ServeMux
}

// New creates the PhantomShop application.
func New() *App {
	db.Init()

	app := &App{mux: http.NewServeMux()}

	// Static files
	app.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("internal/shop/static"))))

	// Public pages
	app.mux.HandleFunc("/", handleHome)
	app.mux.HandleFunc("/products", handleProducts)
	app.mux.HandleFunc("/product/", handleProductDetail)
	app.mux.HandleFunc("/search", handleSearch)
	app.mux.HandleFunc("/contact", handleContact)

	// Auth
	app.mux.HandleFunc("/login", handleLogin)
	app.mux.HandleFunc("/register", handleRegister)
	app.mux.HandleFunc("/logout", handleLogout)
	app.mux.HandleFunc("/forgot-password", handleForgotPassword)
	app.mux.HandleFunc("/reset-password", handleResetPassword)

	// User area
	app.mux.HandleFunc("/profile", handleProfile)
	app.mux.HandleFunc("/profile/edit", handleProfileEdit)
	app.mux.HandleFunc("/profile/avatar", handleAvatarUpload)
	app.mux.HandleFunc("/orders", handleOrders)
	app.mux.HandleFunc("/order/", handleOrderDetail)

	// Shopping
	app.mux.HandleFunc("/cart", handleCart)
	app.mux.HandleFunc("/cart/add", handleCartAdd)
	app.mux.HandleFunc("/checkout", handleCheckout)
	app.mux.HandleFunc("/apply-coupon", handleApplyCoupon)
	app.mux.HandleFunc("/review", handleReview)

	// API (vulnerable)
	app.mux.HandleFunc("/api/user/", handleAPIUser)
	app.mux.HandleFunc("/api/products", handleAPIProducts)
	app.mux.HandleFunc("/api/order/", handleAPIOrder)
	app.mux.HandleFunc("/api/newsletter", handleNewsletter)
	app.mux.HandleFunc("/api/export", handleExport)
	app.mux.HandleFunc("/api/import", handleImport)

	// Admin
	app.mux.HandleFunc("/admin", handleAdmin)
	app.mux.HandleFunc("/admin/invoice", handleInvoice)

	// Vulnerabilities info
	app.mux.HandleFunc("/vulns", handleVulnList)
	app.mux.HandleFunc("/scoreboard", handleScoreboard)
	app.mux.HandleFunc("/flag", handleFlagSubmit)

	// Extra vulnerability endpoints (28 more vulns = 50 total)
	RegisterExtraRoutes(app.mux)

	// Internal service (for SSRF)
	go startInternalService()

	return app
}

// Start launches the server.
func (app *App) Start(addr string) error {
	return http.ListenAndServe(addr, app.mux)
}
