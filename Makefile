
.PHONY: clean check-nix check-git
.DEFAULT_GOAL = all

GIT_COMMIT = $(shell git rev-parse HEAD)
SOURCES = include/*.inc

all: check-nix check-git ${SOURCES}
	@echo "Starting build with git commit ID: ${GIT_COMMIT}"
	nix-build --argstr ref ${GIT_COMMIT}

clean:
	rm result || true

check-git:
	@command -v git > /dev/null 2>&1 || (echo "Must have git installed on your system." && exit 1)
	@git rev-parse HEAD >/dev/null 2>&1 || (echo "Must be running inside of a git repository." && exit 1)

check-nix:
	@command -v nix-build > /dev/null 2>&1 || (echo "Must have Nix installed on your system." && exit 1)
