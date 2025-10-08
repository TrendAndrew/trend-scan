FROM alpine:3.9

RUN apk add --update --no-cache bash

COPY tmas /

ENTRYPOINT ["/tmas"]
