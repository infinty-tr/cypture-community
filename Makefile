.PHONY: run build vet fmt tidy clean

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
