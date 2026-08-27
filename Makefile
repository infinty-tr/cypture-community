.PHONY: run build vet fmt tidy clean docker-ce docker-ce-up docker-ce-down

run:
	go run ./cmd/cypture

build:
	go build -o bin/cypture ./cmd/cypture
	go build -o bin/cypture-engine ./cmd/cypture-engine

vet:
	go vet ./...

fmt:
	gofmt -w internal cmd

tidy:
	go mod tidy

clean:
	rm -rf bin data/cypture.db*

# Build the per-engagement engine image. cypture-agent is installed inside the image for
# the container's own OS/arch (see Dockerfile); we only stage our own linux engine.
docker-image:
	mkdir -p docker/bin
	CGO_ENABLED=0 GOOS=linux go build -o docker/bin/cypture-engine ./cmd/cypture-engine
	@OLD=$$(docker images -q cypture-engine:latest); \
	docker build -f docker/Dockerfile -t cypture-engine:latest . && \
	NEW=$$(docker images -q cypture-engine:latest); \
	if [ -n "$$OLD" ] && [ "$$OLD" != "$$NEW" ]; then \
	  echo "eski cypture-engine image siliniyor: $$OLD"; \
	  docker rmi "$$OLD" 2>/dev/null || true; \
	fi

.PHONY: docker-image

# ── Community Edition all-in-one image (recommended) ──────────────────────────
# Self-contained: server + engine + opencode + agents + recon toolchain in one
# image. `docker compose up` gives a working scan instance on any machine.
docker-ce:
	docker compose build

docker-ce-up:
	docker compose up -d --build
	@echo "Cypture CE → http://localhost:7777/admin"

docker-ce-down:
	docker compose down
