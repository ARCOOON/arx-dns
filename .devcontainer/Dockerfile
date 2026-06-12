FROM golang:bookworm

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-dnsutils \
        ca-certificates \
        curl \
        dnsutils \
        git \
        iproute2 \
        iputils-ping \
        libcap2-bin \
        sudo \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd -s /bin/bash --uid "${USER_UID}" --gid "${USER_GID}" -m "${USERNAME}" \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${USERNAME}" \
    && chmod 0440 "/etc/sudoers.d/${USERNAME}"

WORKDIR /workspace

USER "${USERNAME}"

ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    PATH="/home/${USERNAME}/go/bin:/usr/local/go/bin:${PATH}"

RUN go version
