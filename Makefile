# referenced from https://github.com/notaryproject/notation/blob/main/Makefile
MODULE         = github.com/shizhMSFT/notation-cose
COMMANDS       = notation-cose
GIT_TAG        = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
BUILD_METADATA =
ifeq ($(GIT_TAG),) # unreleased build
    GIT_COMMIT     = $(shell git rev-parse HEAD)
    GIT_STATUS     = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "unreleased")
	BUILD_METADATA = $(GIT_COMMIT).$(GIT_STATUS)
endif
LDFLAGS        = -X $(MODULE)/internal/version.BuildMetadata=$(BUILD_METADATA)
GO_BUILD_FLAGS = --ldflags="$(LDFLAGS)"

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: build

.PHONY: FORCE
FORCE:

bin/%: cmd/% FORCE
	go build $(GO_BUILD_FLAGS) -o $@ ./$<

.PHONY: download
download: ## download dependencies via go mod
	go mod download

.PHONY: build
build: $(addprefix bin/,$(COMMANDS)) ## builds binaries

.PHONY: clean
clean:
	git status --ignored --short | grep '^!! ' | sed 's/!! //' | xargs rm -rf

.PHONY: test
test:
	go test ./... -coverprofile cover.out

.PHONY: check-line-endings
check-line-endings: ## check line endings
	! find . -name "*.go" -type f -exec file "{}" ";" | grep CRLF

.PHONY: fix-line-endings
fix-line-endings: ## fix line endings
	find . -type f -name "*.go" -exec sed -i -e "s/\r//g" {} +

.PHONY: install
install: install-notation-cose ## install the notation plugins

.PHONY: install-notation-cose
install-notation-cose: bin/notation-cose ## installs the notation cose plugin
	cp $< ~/.config/notation/plugins/cose/notation-cose
