# Minimal runtime image.
FROM gcr.io/distroless/base-debian12

WORKDIR /
COPY --chmod=755 main /main

EXPOSE 8443
USER 1000:1000
ENTRYPOINT ["./main"]