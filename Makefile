all: push

VERSION = v0.1.0
TAG = $(VERSION)
PREFIX = harbor-cicd.taco-cat.xyz/dev/dev-donggyu

DOCKERFILEPATH =  build
DOCKERFILE = Dockerfile.keycloak-cli

GIT_COMMIT = $(shell git rev-parse --short HEAD)

export DOCKER_BUILDKIT = 1

container:
	DOCKER_BUILDKIT=1 docker build --platform linux/amd64 $(DOCKER_BUILD_OPTIONS) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg VERSION=$(VERSION) -f $(DOCKERFILEPATH)/$(DOCKERFILE) -t $(PREFIX):$(TAG) .

push: container
	docker push $(PREFIX):$(TAG)
