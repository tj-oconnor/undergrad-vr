#include <stdio.h>

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln(char* msg) {
    char buf[8];
    puts(msg);
    gets(buf);
}

int main() {
  vuln("Never gonna get a shell >>> ");
}

