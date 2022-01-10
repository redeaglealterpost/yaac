UID := $(shell id -u)

dev:
	DOCKER_BUILDKIT=1 docker build -t yaac-php-dev -f Dockerfile .
	docker run -it --rm -v $(PWD):/app -v $(HOME)/.composer:/.composer -u $(UID) -w /app yaac-php-dev bash