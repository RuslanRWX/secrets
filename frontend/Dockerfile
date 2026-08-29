# syntax=docker/dockerfile:1

FROM node:20-alpine AS build

ARG VERSION=dev
ENV APP_VERSION=$VERSION

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# nginx-unprivileged listens on 8080 as a non-root user, which is what the
# Kubernetes securityContext expects.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# API_URL is substituted into the config at container start, so the same image
# works in Compose and in Kubernetes without a rebuild.
ENV API_URL=http://secrets-api:8080

COPY --chown=nginx:nginx nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

EXPOSE 8080
