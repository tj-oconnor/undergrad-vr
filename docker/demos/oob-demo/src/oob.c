#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

char * books[] = {
  "Practical Reverse Engineering\0",
  "The Ghidra Book\0",
  "Green Eggs and Ham\0",
  "The 48 Laws of Power\0"
};

void win() {
   system("cat flag.txt");  
}

void vuln() {
    int book_choice;
    printf("\nWhich book would you like to read [0-3] <<< ");
    scanf("%i",&book_choice);
    if (book_choice==0) {
       printf(">>> An Excellent Choice: %s",books[book_choice]);
       exit(0);
    }
    else {
      printf(">>> This book: %s is old. Replace it with a new book.\n", books[book_choice]);
      printf("Name of New Book >>>");
      scanf("%24s",&books[book_choice]);
    }
}

int main() {
    while (1) {
      vuln();
    }
}
