/**
 *  Vulnerable program to demonstrate FILE structure exploitation
 *  for the recent libc - bypassing the new 'vtable' check
 *
 *  https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
 */

#include <stdio.h>
#include <unistd.h>

char fake_file[0x200];

int main() {
  FILE *fp;
  puts("Leaking libc address of stdout:");
  printf("%p\n", stdout); // Emulating libc leak
  puts("Enter fake file structure");
  read(0, fake_file, 0x200);
  fp = (FILE *)&fake_file;
  fclose(fp);
  return 0;
}
