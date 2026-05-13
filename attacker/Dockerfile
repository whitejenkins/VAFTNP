FROM lscr.io/linuxserver/openssh-server:latest

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends responder \
    && rm -rf /var/lib/apt/lists/*
