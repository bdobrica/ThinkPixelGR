FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/thinkpixelgr ./cmd/thinkpixelgr

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/thinkpixelgr /thinkpixelgr
COPY configs/config.yaml /configs/config.yaml
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/thinkpixelgr", "-config", "/configs/config.yaml"]
