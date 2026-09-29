FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY test/lab/app ./test/lab/app
RUN CGO_ENABLED=0 go build -mod=readonly -o /lab ./test/lab/app

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN adduser -D -H lab
USER lab
COPY --from=build /lab /lab
EXPOSE 8080
ENTRYPOINT ["/lab"]
