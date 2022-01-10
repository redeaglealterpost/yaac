FROM php:7.2-cli
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN apt update && apt install git unzip -y