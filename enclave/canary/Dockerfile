FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf install -y python3 python3-cryptography ca-certificates && dnf clean all
COPY libnsm.so /usr/lib64/libnsm.so
COPY server.py /app/server.py
# Hardware canary only: no credentials, persistence or production route.
ENTRYPOINT ["python3", "/app/server.py"]
