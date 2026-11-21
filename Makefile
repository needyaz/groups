# The same checks CI runs (.github/workflows/ci.yml), as make targets.
.PHONY: analyze test

## dart analyze
analyze:
	dart pub get
	dart analyze

## dart test (needs libsodium, as in CI)
test:
	dart pub get
	dart test
