FROM golang:1.24 as build-env

ARG TARGETARCH
ARG VERSION=dev

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=$TARGETARCH

WORKDIR /tmp/secrets-store-csi-driver-provider-1password
COPY . ./
RUN go get -t ./...
RUN make licensessave
RUN go install \
    -trimpath \
    -ldflags "-s -w -extldflags '-static' -X 'main.version=${VERSION}'" \
    github.com/martyn-meister/secrets-store-csi-driver-provider-1password

FROM gcr.io/distroless/static-debian10
COPY --from=build-env /tmp/secrets-store-csi-driver-provider-1password/licenses /licenses
COPY --from=build-env /go/bin/secrets-store-csi-driver-provider-1password /bin/
ENTRYPOINT ["/bin/secrets-store-csi-driver-provider-1password"]
