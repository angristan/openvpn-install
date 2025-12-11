.PHONY: test test-build test-up test-down test-logs test-clean

# Run the full test suite
test: test-build test-up
	@echo "Waiting for tests to complete..."
	@for i in $$(seq 1 180); do \
		if docker logs openvpn-client 2>&1 | grep -q "ALL TESTS PASSED"; then \
			echo "✓ Tests passed!"; \
			$(MAKE) test-down; \
			exit 0; \
		fi; \
		if docker logs openvpn-client 2>&1 | grep -q "FAIL:"; then \
			echo "✗ Tests failed!"; \
			docker logs openvpn-client; \
			$(MAKE) test-down; \
			exit 1; \
		fi; \
		echo "Waiting... ($$i/180)"; \
		sleep 2; \
	done; \
	echo "Timeout waiting for tests"; \
	$(MAKE) test-down; \
	exit 1

# Build test containers
test-build:
	BASE_IMAGE=$(BASE_IMAGE) docker compose build

# Start test containers
test-up:
	docker compose up -d

# Stop and remove test containers
test-down:
	docker compose down -v --remove-orphans

# View logs
test-logs:
	docker compose logs -f

# View server logs only
test-logs-server:
	docker logs -f openvpn-server

# View client logs only
test-logs-client:
	docker logs -f openvpn-client

# Full cleanup
test-clean: test-down
	docker rmi openvpn-install-openvpn-server openvpn-install-openvpn-client 2>/dev/null || true
	docker volume prune -f

# Interactive shell into server container
test-shell-server:
	docker exec -it openvpn-server /bin/bash

# Interactive shell into client container
test-shell-client:
	docker exec -it openvpn-client /bin/bash

# Test specific distributions
test-ubuntu-18.04:
	$(MAKE) test BASE_IMAGE=ubuntu:18.04

test-ubuntu-20.04:
	$(MAKE) test BASE_IMAGE=ubuntu:20.04

test-ubuntu-22.04:
	$(MAKE) test BASE_IMAGE=ubuntu:22.04

test-ubuntu-24.04:
	$(MAKE) test BASE_IMAGE=ubuntu:24.04

test-debian-11:
	$(MAKE) test BASE_IMAGE=debian:11

test-debian-12:
	$(MAKE) test BASE_IMAGE=debian:12

test-fedora-40:
	$(MAKE) test BASE_IMAGE=fedora:40

test-fedora-41:
	$(MAKE) test BASE_IMAGE=fedora:41

test-rocky-8:
	$(MAKE) test BASE_IMAGE=rockylinux:8

test-rocky-9:
	$(MAKE) test BASE_IMAGE=rockylinux:9

test-almalinux-8:
	$(MAKE) test BASE_IMAGE=almalinux:8

test-almalinux-9:
	$(MAKE) test BASE_IMAGE=almalinux:9

test-oracle-8:
	$(MAKE) test BASE_IMAGE=oraclelinux:8

test-oracle-9:
	$(MAKE) test BASE_IMAGE=oraclelinux:9

test-amazon-2023:
	$(MAKE) test BASE_IMAGE=amazonlinux:2023

test-arch:
	$(MAKE) test BASE_IMAGE=archlinux:latest

test-centos-stream-9:
	$(MAKE) test BASE_IMAGE=quay.io/centos/centos:stream9

test-opensuse-leap:
	$(MAKE) test BASE_IMAGE=opensuse/leap:16.0

test-opensuse-tumbleweed:
	$(MAKE) test BASE_IMAGE=opensuse/tumbleweed

# Test all distributions (runs sequentially)
test-all:
	$(MAKE) test-ubuntu-18.04
	$(MAKE) test-ubuntu-20.04
	$(MAKE) test-ubuntu-22.04
	$(MAKE) test-ubuntu-24.04
	$(MAKE) test-debian-11
	$(MAKE) test-debian-12
	$(MAKE) test-fedora-40
	$(MAKE) test-fedora-41
	$(MAKE) test-rocky-8
	$(MAKE) test-rocky-9
	$(MAKE) test-almalinux-8
	$(MAKE) test-almalinux-9
	$(MAKE) test-oracle-8
	$(MAKE) test-oracle-9
	$(MAKE) test-amazon-2023
	$(MAKE) test-arch
	$(MAKE) test-centos-stream-9
	$(MAKE) test-opensuse-leap
	$(MAKE) test-opensuse-tumbleweed
