FROM alpine:3.17
# Define build-time variables
ARG WAITRESS_PORT

# Set the build-time variable as an environment variable
ENV WAITRESS_PORT=${WAITRESS_PORT}

# Copy files
COPY ./src /home/api/

# Update apt repository and install dependencies
RUN apk --no-cache -U add \
    python3 \
    py3-pip \
    curl \
    python3-dev && \
    addgroup -g 2000 api && \
    adduser -S -s /bin/ash -u 2000 -D -g 2000 api && \
    pip3 install setuptools \
    wheel \
    flask \
    waitress \
    requests \
    cryptography \
    pytz && \
    cd /home/api && \
    mkdir log_data && \
    chown api:api -R /home/api/* 

WORKDIR /home/api
USER api:api

CMD waitress-serve --port=$WAITRESS_PORT log_api:app

