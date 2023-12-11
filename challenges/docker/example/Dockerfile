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

