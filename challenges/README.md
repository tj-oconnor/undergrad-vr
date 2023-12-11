# Vulnerable Binary Challenge Hosting

We standardized deploying course challenges (homework assignments) to our hosting infrastructure at [ctfd.io](https://ctfd.io). 

## Base Image

[base/](base/) provides a base image with all the necessary tools and permissions to host the challenges. We make a limited privilege user account called ``ctf`` that executes the challenge binaries. We build on top of ``alpine`` since it is a lightweight container known for small size. We also install the [pwninit](https://github.com/io12/pwninit/) utility to allow us to patch binaries with specific libc versions. 

```
FROM alpine:latest

RUN apk update && apk upgrade
RUN apk add --no-cache socat wget make patchelf

RUN adduser -D ctf
COPY start.sh /start.sh
RUN chmod 755 /start.sh

RUN wget -O /bin/pwninit https://github.com/io12/pwninit/releases/download/3.2.0/pwninit && \
    chmod +x /bin/pwninit 

WORKDIR /home/ctf/
EXPOSE 9000

CMD ["/start.sh"]
```

## Building A Challenge Hosting Container

[example/](example/) depicts an example of hosting a vulnerable binary. Here we copy over all the ``flag``, ``chal.bin``, ``libc``, and ``ld`` files to a ``tjoconnor/vr-hosting`` base. We then set the permisisons of the flag to be read-only by the user ``ctf``. Standardizing the libc version proves important for exploit challenges that rely on it, so we optionally patch the libc version using [pwninit](https://github.com/io12/pwninit/). 

```
FROM tjoconnor/vr-hosting

COPY flag.txt /home/ctf/flag.txt
COPY ./bin/chal.bin /home/ctf
COPY libc/libc.so.6 /opt/libc.so.6 
COPY libc/ld-2.27.so /opt/ld.so

RUN chown root:root /home/ctf/flag.txt
RUN chmod 644 /home/ctf/flag.txt

RUN pwninit --bin /home/ctf/chal.bin --ld /opt/ld.so --libc /opt/libc.so.6 --no-template 
RUN mv /home/ctf/chal.bin_patched /home/ctf/chal.bin

RUN chmod +x /home/ctf/chal.bin
```

## Building and Testing Locally

To build a container we simple ``docker build -t ret2plt .``  The container exposes the binary on TCP port 9000, so we'll need to port foward a local port to connect to it. We can do that using ``docker run -p9000:9000 ret2plt`` and then attempt to connect to it.

```
nc localhost 9000
Never gonna get a shell >>> 
```

## Building and Deploying

To build a container we simple ``docker build -t ret2plt .`` and then deploy to our infrastructure. In the case our infrastructure at [ctfd.io](https://ctfd.io). We simply need to ``docker tag ret2plt <hosting location>`` and ``docker push <hosting location>`` the image using the repository names for the hosting environment. 

