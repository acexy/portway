GO ?= go
TARGET_DIR ?= target

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf development)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BUILDINFO_PACKAGE := github.com/acexy/portway/internal/buildinfo
LDFLAGS := -s -w \
	-X $(BUILDINFO_PACKAGE).Version=$(VERSION) \
	-X $(BUILDINFO_PACKAGE).Commit=$(COMMIT) \
	-X $(BUILDINFO_PACKAGE).BuildTime=$(BUILD_TIME)

RELEASE_ARCHIVES := \
	$(TARGET_DIR)/portway-linux-amd64.tar \
	$(TARGET_DIR)/portway-linux-arm64.tar \
	$(TARGET_DIR)/portway-darwin-amd64.tar \
	$(TARGET_DIR)/portway-darwin-arm64.tar \
	$(TARGET_DIR)/portway-win-amd64.tar

.PHONY: help build release force

help:
	@printf '%s\n' \
		'Portway build targets:' \
		'  make build    Build portway and portwayd for the current platform' \
		'  make release  Build and package all supported release platforms' \
		'' \
		'Optional variables:' \
		'  VERSION       Release version (default: git describe)' \
		'  COMMIT        Source revision (default: current Git revision)' \
		'  BUILD_TIME    UTC build timestamp' \
		'  TARGET_DIR    Output directory (default: target)'

build:
	@mkdir -p "$(TARGET_DIR)/bin"
	CGO_ENABLED=0 "$(GO)" build -trimpath -ldflags "$(LDFLAGS)" \
		-o "$(TARGET_DIR)/bin/portway" ./cmd/portway
	CGO_ENABLED=0 "$(GO)" build -trimpath -ldflags "$(LDFLAGS)" \
		-o "$(TARGET_DIR)/bin/portwayd" ./cmd/portwayd

release: $(RELEASE_ARCHIVES)
	@printf 'Release archives created in %s\n' "$(TARGET_DIR)"

force:

define RELEASE_RULES
$(TARGET_DIR)/build/$(1)-$(2)/portway$(3): force
	@mkdir -p "$(TARGET_DIR)/build/$(1)-$(2)"
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) "$(GO)" build -trimpath \
		-ldflags "$(LDFLAGS)" -o "$$@" ./cmd/portway

$(TARGET_DIR)/build/$(1)-$(2)/portwayd$(3): force
	@mkdir -p "$(TARGET_DIR)/build/$(1)-$(2)"
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) "$(GO)" build -trimpath \
		-ldflags "$(LDFLAGS)" -o "$$@" ./cmd/portwayd

$(TARGET_DIR)/portway-$(4)-$(2).tar: \
		$(TARGET_DIR)/build/$(1)-$(2)/portway$(3) \
		$(TARGET_DIR)/build/$(1)-$(2)/portwayd$(3)
	tar -C "$(TARGET_DIR)/build/$(1)-$(2)" -cf "$$@" \
		"portway$(3)" "portwayd$(3)"
endef

$(eval $(call RELEASE_RULES,linux,amd64,,linux))
$(eval $(call RELEASE_RULES,linux,arm64,,linux))
$(eval $(call RELEASE_RULES,darwin,amd64,,darwin))
$(eval $(call RELEASE_RULES,darwin,arm64,,darwin))
$(eval $(call RELEASE_RULES,windows,amd64,.exe,win))
