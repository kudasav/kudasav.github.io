# syntax=docker/dockerfile:1

# ---------- Stage 1: build the static site ----------
# Jekyll needs Ruby; Webpack/Tailwind need Node. Start from Ruby and add Node.
FROM ruby:3.2.2-slim AS build

# Install Node.js (for Webpack/Tailwind) and build tooling for native gems.
ENV NODE_VERSION=22
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        ca-certificates \
        git \
    && curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Ruby gems first (cached unless Gemfile changes).
COPY Gemfile Gemfile.lock ./
RUN gem install bundler -v 2.3.4 \
    && bundle config set --local without 'development test' \
    && bundle install --jobs 4 --retry 3

# Install Node dependencies (cached unless package files change).
COPY package.json package-lock.json ./
RUN npm ci

# Copy the rest of the source and build.
COPY . .
RUN JEKYLL_ENV=production npm run build

# ---------- Stage 2: serve the built site ----------
FROM nginx:1.27-alpine AS serve

# Serve the generated static site.
COPY --from=build /app/_site /usr/share/nginx/html

# Custom config: listen on 4000 and emit relative redirects (see nginx.conf).
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 4000

CMD ["nginx", "-g", "daemon off;"]
