FROM python:3.10-bullseye

ENTRYPOINT ["/bin/bash"]
ENV PATH="/root/.cargo/bin:$PATH"

COPY . /hsmk
WORKDIR /hsmk

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    pip install -v .
