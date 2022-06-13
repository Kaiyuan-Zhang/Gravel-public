FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt update && apt install -y -qq --no-install-recommends \
        build-essential vim cmake git llvm-13-dev libpython3-dev ipython3 python3-pip\
        ninja-build libboost-dev libelf-dev \
        ca-certificates libpsl5 libssl3 openssl publicsuffix wget

RUN pip3 install z3-solver graphviz

WORKDIR /z3-build
RUN wget https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.8.17.tar.gz && tar zxf z3-4.8.17.tar.gz
WORKDIR /z3-build/z3-z3-4.8.17
RUN mkdir build && cd build && cmake -G "Ninja" ../ && ninja && ninja install


# adding a user
RUN groupadd user && groupadd admin
RUN useradd -rm -d /home/user -s /bin/bash -g user -G admin -u 1000 -p "$(openssl passwd -1 user)" user
USER user
WORKDIR /home/user

CMD /bin/bash
