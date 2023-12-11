#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[8];
    read(0,&buf,0x1337);
}

int main() {
    vuln();
    system("echo '<<< no shell for you'");

}
