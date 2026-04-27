CC       = cc
CFLAGS   = -std=c99 -Wall -Wextra -Wno-unused-parameter -Wno-format
CFLAGS  += -I ngx_compat -I ../src -I vendor/nxe-json/src
CFLAGS  += $(shell pkg-config --cflags jansson)
CFLAGS  += $(shell pkg-config --cflags openssl 2>/dev/null)
LDFLAGS  = $(shell pkg-config --libs jansson)
LDFLAGS += $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Enable HMAC for the test build so we exercise that path too.
CFLAGS  += -DNXE_JWX_HAVE_HMAC=1

SRCS = test_runner.c \
       test_crypto.c \
       ngx_compat/ngx_stub.c \
       vendor/nxe-json/src/nxe_json.c \
       ../src/nxe_jwx_decode.c \
       ../src/nxe_jwx_jwks.c \
       ../src/nxe_jwx_jws.c \
       ../src/nxe_jwx_claims.c

test_runner: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

test_runner_asan: $(SRCS)
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g \
		-o $@ $(SRCS) $(LDFLAGS) -fsanitize=address

test_runner_cov: $(SRCS)
	$(CC) $(CFLAGS) --coverage -g -O0 -o $@ $(SRCS) $(LDFLAGS) --coverage

test: test_runner
	./test_runner

test-asan: test_runner_asan
	./test_runner_asan

test-cov: test_runner_cov
	@rm -f *.gcda
	./test_runner_cov
	@echo ""
	@echo "=== Coverage Summary (src/) ==="
	@LC_ALL=C gcov -n *nxe_jwx*.gcda 2>/dev/null \
		| awk '/^File.*\.\.\/src\// { file=$$0 } \
		       /^Lines executed:/ && file { print file; print $$0; file="" }'

clean:
	rm -f test_runner test_runner_asan test_runner_cov *.gcno *.gcda *.gcov

.PHONY: test test-asan test-cov clean
