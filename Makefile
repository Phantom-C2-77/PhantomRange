.PHONY: build run clean docker-build docker-run docker-stop reset-db

APP      := phantomshop
PORT     := 9000

## ── Local ──────────────────────────────────

build:
	go build -o $(APP) ./cmd/server/

run: build
	./$(APP) -addr :$(PORT)

clean:
	rm -f $(APP)
	rm -f build/server

reset-db:
	rm -f data/shop.db
	@echo "Database reset — will re-seed on next start."

## ── Docker ─────────────────────────────────

docker-build:
	docker build -t $(APP) .

docker-run:
	docker compose up -d
	@echo "PhantomShop running at http://localhost:$(PORT)"

docker-stop:
	docker compose down

docker-reset:
	docker compose down -v
	@echo "Volumes removed — database will re-seed on next start."
