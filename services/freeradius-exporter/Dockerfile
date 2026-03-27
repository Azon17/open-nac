FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
RUN go install github.com/bvantagelimited/freeradius_exporter@latest

FROM alpine:3.20
COPY --from=builder /go/bin/freeradius_exporter /usr/local/bin/freeradius_exporter
EXPOSE 9812
ENTRYPOINT ["freeradius_exporter"]
