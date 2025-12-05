.PHONY: test test-build test-up test-down test-logs test-clean

# Run the full test suite
test: test-build test-up
	@echo "Waiting for tests to complete..."
	@for i in $$(seq 1 60); do \
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
		echo "Waiting... ($$i/60)"; \
		sleep 2; \
	done; \
	echo "Timeout waiting for tests"; \
	$(MAKE) test-down; \
	exit 1

# Build test containers
test-build:
	docker compose build

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
