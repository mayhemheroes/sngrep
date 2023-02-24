FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake pkg-config libtool libncurses5-dev libpcap-dev clang

COPY . /repo
WORKDIR /repo
RUN ./bootstrap.sh
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
WORKDIR /repo/src
RUN rm sngrep-main.o
RUN clang++ *.o /repo/mayhem/fuzz_strtrim.cpp -lpcap  curses/*.o -lform -lpanel -lmenu -lncurses -o /fuzz -fsanitize=fuzzer,address

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_strtrim
