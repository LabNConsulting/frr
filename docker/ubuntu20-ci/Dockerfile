FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn
# Update Ubuntu Software repository
RUN apt update && \
    apt-get install -y \
        autoconf \
        automake \
        bison \
        build-essential \
        curl \
        flex \
        gdb \
        git \
        install-info \
        iproute2 \
        iputils-ping \
        libc-ares-dev \
        libcap-dev \
        libelf-dev \
        libjson-c-dev \
        liblua5.3-dev \
        libpam0g-dev \
        libprotobuf-c-dev \
        libreadline-dev \
        libsnmp-dev \
        libssl-dev \
        libtool \
        lua5.3 \
        make \
        net-tools \
        perl \
        pkg-config \
        protobuf-c-compiler \
        python2 \
        python3-dev \
        python3-pip \
        python3-sphinx \
        snmp \
        snmp-mibs-downloader \
        snmpd \
        sudo \
        texinfo \
        time \
        tshark \
        valgrind \
        yodl \
    && \
    download-mibs && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py && \
    python2 /tmp/get-pip.py && \
    rm -f  /tmp/get-pip.py && \
    python3 -m pip install wheel && \
    python3 -m pip install pytest && \
    python3 -m pip install pytest-xdist && \
    python3 -m pip install "scapy>=2.4.2" && \
    python3 -m pip install xmltodict && \
    python3 -m pip install grpcio grpcio-tools && \
    python2 -m pip install 'exabgp<4.0.0'

RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

#for libyang 2
RUN apt-get install -y cmake libpcre2-dev

# Install custom socat required by pim6d topotests
RUN git clone https://github.com/opensourcerouting/socat.git
RUN cd socat && autoconf
RUN cd socat && ./configure --prefix=/usr && make && make install

RUN python3 -m pip install pytest-sugar

USER frr:frr

# build and install libyang2
RUN cd && pwd && ls -al && \
    git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v2.0.0 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
          -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j $(nproc) && \
    sudo make install

COPY --chown=frr:frr . /home/frr/frr/

RUN cd && ls -al && ls -al frr

RUN cd ~/frr && \
    ./bootstrap.sh && \
    ./configure \
       --prefix=/usr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-sharpd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --enable-snmp=agentx \
       --enable-scripting \
       --with-pkg-extra-version=-my-manual-build && \
    make -j $(nproc) && \
    sudo make install

RUN cd ~/frr && make check || true

COPY docker/ubuntu20-ci/docker-start /usr/sbin/docker-start
CMD ["/usr/sbin/docker-start"]
