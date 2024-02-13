FROM kalilinux/kali-rolling:latest

MAINTAINER tj <toconnor@fit.edu>
LABEL maintainer="TJ <toconnor@fit.edu>"

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York

RUN apt-get clean -y && \
    apt-get update -qq -y && \
    apt-get upgrade -qq -y && \
    apt-get update -y 

################################################################################
# cross-compilation stuff for i386 first
################################################################################
RUN dpkg --add-architecture i386 && \
    apt-get update -y && \
    apt-get -y install -o APT::Immediate-Configure=false \
       libc6-i386 \
       libstdc++6:i386 \
       libc6-dev-i386 \
       --no-install-recommends

################################################################################
# apt-get installs
################################################################################
RUN apt-get install -y --ignore-missing \
    apt-utils \
    autoconf \
    autotools-dev \
    automake \
    bc \ 
    binutils \
    build-essential \
    clang \
    cmake \
    cpio \
    elfutils \
    file \
    flawfinder \
    gcc \
    gcc-multilib \
    gcc-12-plugin-dev \
    gdb \
    gdb-multiarch \
    gdbserver \
    git \
    jq \
    libedit-dev \
    libelf-dev \
    locales \
    ltrace \
    make \
    man \
    nano \
    nasm \
    net-tools \
    patchelf \ 
    pkg-config \
    python3-dev \
    python3-pip \
    qemu-system-common \
    qemu-system-misc \
    qemu-system-x86 \
    qemu-user \
    rpm2cpio \
    ruby \
    ruby-dev \
    strace \
    sudo \
    tmux \
    wget \
    xxd \
    wget \
    zstd \
    zsh \
    --fix-missing && \
       rm -rf /var/lib/apt/lists/*

################################################################################
# python3 pip installs
################################################################################
RUN python3 -m pip install --upgrade pip 

RUN python3 -m pip install --no-cache-dir \
    angr \
    angrop \
    autopep8 \
    capstone \
    cython \
    keystone-engine \
    maat \
    pwncli \
    pwnscripts \
    pycipher \
    pycryptodome \
    pymaat \ 
    pwntools \
    python-magic \
    qiling \
    ropgadget \
    ropper \
    unicorn 

################################################################################
# ruby installs
################################################################################

# install ruby gems
RUN gem install one_gadget seccomp-tools && \
    rm -rf /var/lib/gems/2.*/cache/*

################################################################################
# individual software installs
################################################################################

# install rappel for emulating assembly instructions
RUN cd /opt/ && \
    git clone https://github.com/yrp604/rappel && \
    cd rappel && CC=clang make
ENV PATH=$PATH:/opt/rappel/bin/

# install pwndbg (gdb enhancement)
RUN cd /opt/ && git clone https://github.com/pwndbg/pwndbg && \
  cd pwndbg && \
  ./setup.sh

# install pwninit for patching bins for ctfs     
RUN wget -O /bin/pwninit https://github.com/io12/pwninit/releases/download/3.3.1/pwninit && \
    chmod +x /bin/pwninit 

# downloads libc-database
RUN cd /opt/ && \
    git clone https://github.com/niklasb/libc-database && \
    cd /opt/libc-database &&\
    ./get ubuntu 

################################################################################
# cross-compilation stuff (armhf/armel) last
################################################################################
RUN dpkg --add-architecture armhf && \
    dpkg --add-architecture armel && \
    apt-get update -y && \
    apt-get -y install -o APT::Immediate-Configure=false \
       gcc-aarch64-linux-gnu \
       gcc-arm-linux-gnueabi \
       gcc-arm-linux-gnueabihf \
       binutils-aarch64-linux-gnu \
       --no-install-recommends && \
       rm -rf /var/lib/apt/lists/*

################################################################################
# environment
################################################################################

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8 

# install omz theme
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.5/zsh-in-docker.sh)" -- \
    -t crunch

RUN chsh -s /bin/zsh
RUN echo "set-option -g default-shell /bin/zsh" > /root/.tmux.conf
RUN touch ~/.hushlogin
RUN echo "flag{fake-flag}" > /flag.txt

################################################################################
# copy over demos
################################################################################

ADD demos /demos
WORKDIR /demos
RUN cd /demos

ENTRYPOINT ["/bin/tmux"]
