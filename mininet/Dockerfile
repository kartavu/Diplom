FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Устанавливаем необходимые пакеты для сборки и других зависимостей
RUN apt-get update && apt-get install -y \
    sudo \
    python3 \
    python3-pip \
    mininet \
    telnet \
    asterisk \
    dnsutils \
    iproute2 \
    iputils-ping \
    net-tools \
    openvswitch-switch \
    openvswitch-common \
    iperf3 \
    ifupdown \
    bind9 \
    inetutils-telnetd \
    iptables \
    git \
    pkg-config \
    dh-autoreconf \
    ncurses-dev \
    build-essential \
    libssl-dev \
    libpcap-dev \
    libncurses5-dev \
    libsctp-dev \
    lksctp-tools \
    cmake \
    libgsl-dev \
    && rm -rf /var/lib/apt/lists/*

# Клонируем и устанавливаем SIPp
RUN git clone https://github.com/SIPp/sipp.git /opt/sipp && \
    cd /opt/sipp && \
    cmake . -DUSE_SSL=1 -DUSE_SCTP=1 -DUSE_PCAP=1 -DUSE_GSL=1 && \
    make all && \
    make install && \
    rm -rf /opt/sipp

# Обновляем pip и устанавливаем Ryu
RUN pip3 install --upgrade pip && \
    pip3 install ryu && \
    pip3 install eventlet==0.30.2 && \
    pip3 install numpy && \
    pip3 install prettytable && \
    pip3 install scikit-learn==1.2.2

# Создаем базу данных Open vSwitch
RUN mkdir -p /var/run/openvswitch && \
    mkdir -p /var/log/openvswitch && \
    mkdir -p /etc/openvswitch && \
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema

RUN useradd -m -s /bin/bash telnetuser && \
    echo "telnetuser:password123" | chpasswd && \
    usermod -aG sudo telnetuser

# Expose ports for OpenFlow communication
EXPOSE 6633 6634

# Запускаем Open vSwitch в user-space режиме
CMD ["/bin/bash", "-c", "/usr/share/openvswitch/scripts/ovs-ctl start --no-ovs-vswitchd && ovs-vswitchd --no-chdir --pidfile --detach && bash"]