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
