FROM kalilinux/kali-rolling:latest

MAINTAINER tj <toconnor@fit.edu>
LABEL maintainer="TJ <toconnor@fit.edu>"

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York

################################################################################
# apt-get installs
################################################################################

RUN apt-get clean -y && \
    apt-get update -qq -y && \
    apt-get upgrade -qq -y && \
    apt-get update -y 

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
    elfutils \
    flawfinder \
    gcc \
    gcc-multilib \
    gcc-12-plugin-dev \
    gdb \
    gdb-multiarch \
    gdbserver \
    git \
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
    ruby \
    ruby-dev \
    strace \
    sudo \
    tmux \
    xxd \
    wget \
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
#RUN cd /opt/ && git clone https://github.com/pwndbg/pwndbg && \
#  cd pwndbg && \
#  ./setup.sh
RUN wget -O /opt/pwndbg.deb https://github.com/pwndbg/pwndbg/releases/download/2023.07.17-pkgs/pwndbg_2023.07.17_amd64.deb
RUN cd /opt && apt install ./pwndbg.deb


# install pwninit for patching bins for ctfs     
RUN wget -O /bin/pwninit https://github.com/io12/pwninit/releases/download/3.3.0/pwninit && \
    chmod +x /bin/pwninit 

# downloads libc-database
RUN cd /opt/ && \
    git clone https://github.com/niklasb/libc-database 

## some cross-compilation stuff
#RUN dpkg --add-architecture armhf && \
#    dpkg --add-architecture armel && \
#    apt-get update -y && \
#    apt-get -y install libssl-dev:armhf \
#                       libssl-dev:armel \
#                       libc6:i386 \
#                       libstdc++6:i386 \
#                       libc6-dev-i386 \
#                       gcc-aarch64-linux-gnu \
#		       gcc-arm-linux-gnueabi \
#   		       gcc-arm-linux-gnueabihf \
#                       binutils-aarch64-linux-gnu && \
#                       rm -rf /var/lib/apt/lists/*

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
ADD demos /demos

WORKDIR /demos
RUN cd /demos
RUN chsh -s /bin/zsh
RUN echo "set-option -g default-shell /bin/zsh" > /root/.tmux.conf
RUN touch ~/.hushlogin
RUN echo "flag{fake-flag}" > /flag.txt

################################################################################
# copy over demos
################################################################################

ENTRYPOINT ["/bin/tmux"]
