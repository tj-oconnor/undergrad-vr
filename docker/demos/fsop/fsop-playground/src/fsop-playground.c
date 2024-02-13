#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void ignore_me() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

int main(int argc, char **argv) {
	FILE *fp = fopen("/dev/random", "r");
	char buf [256];	

	printf("Overwrite ptr >>> ");
	read (0, fp, 0x100);
	printf("<<< Calling fwrite ");
	fwrite(buf, 1, 10, fp);

        printf("\nOverwrite ptr >>> ");
        read (0, fp, 0x100);
	printf("\n<<< Calling fread ");
	fread (buf, 1, 10, fp);

        printf("\nGoodbye!");
        exit(0);
}
