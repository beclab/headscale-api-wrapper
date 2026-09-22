FROM golang:alpine AS build
RUN apk add --no-cache --update git gcc musl-dev
WORKDIR /go/src/app

COPY . .

RUN go mod tidy && go build \
    -o headscale-api-wrapper \
    .

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
COPY --from=build /go/src/app/headscale-api-wrapper /

CMD ["/headscale-api-wrapper"]
