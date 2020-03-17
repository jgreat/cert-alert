FROM golang:1.14-alpine as build

ARG VERSION

ADD . /app

WORKDIR /app

RUN go clean && \
    go mod tidy && \
    go build -v -ldflags "-X 'main.version=$VERSION'"

FROM alpine

COPY --from=build /app/cert-alert /usr/local/bin/cert-alert

RUN apk --no-cache add ca-certificates && \
    addgroup -g 1000 app && \
    adduser -S -G app -u 1000 -s /bin/sh app

USER app

CMD [ "/usr/local/bin/cert-alert" ]
