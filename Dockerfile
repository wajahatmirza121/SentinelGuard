# Optional hardened runner (not exercised in the build sandbox). See README "Run it sandboxed".
FROM python:3.12-slim
RUN useradd -m sentinel
COPY . /src
RUN pip install --no-cache-dir /src && rm -rf /src
USER sentinel
WORKDIR /project
ENTRYPOINT ["sentinel"]
