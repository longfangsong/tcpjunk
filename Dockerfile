FROM ubuntu as builder
RUN apt update && apt install -y curl clang && curl https://sh.rustup.rs -sSf > rustup-init.sh && sh ./rustup-init.sh -y
COPY . .
RUN $HOME/.cargo/bin/cargo build --release

FROM ubuntu
COPY --from=builder ./target/release/tcpjunk .
CMD ["./tcpjunk"]
EXPOSE 8080