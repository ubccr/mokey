#
# Mokey Dockerfile.
#
#
FROM golang:alpine AS build-env
#
#
# Install pre-reqs
RUN apk --no-cache add build-base git gcc ca-certificates
#
# Make the app dir so the binaries have somewhere to go
RUN mkdir /app
RUN mkdir /build
# Do the build
COPY ./ /build
WORKDIR /build
#
# Build Mokey
RUN go generate && env GOOS=linux GOARCH=amd64 go build -o ./mokey main.go && chmod +x mokey && mv mokey /app/mokey
#
#
#################### Create main Docker image ####################
#
FROM ghcr.io/linuxserver/baseimage-alpine:3.18
LABEL maintainer="Aterfax"
#
COPY --from=build-env /app /app/
RUN chmod +x -R /app/