#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <dirent.h>
#include <string.h>

void readFile(void * buffer) {
    buffer = (char *)buffer;
    char *fileCont = malloc(0x1000);
    int *retVal = calloc(1, sizeof(int));
    if (strcmp(buffer, "flag.txt") == 0) {
        puts("\nNo flag for you!");
        free(fileCont);
        *retVal = 0xff;
        pthread_exit((void *)retVal);
    }
    else {
        sleep(1);
        if (access(buffer, F_OK) == 0) {
            FILE * f = fopen(buffer, "r");
            fread(fileCont, 1, 0x1000, f);
            printf("\n\n%s\n", fileCont);
        }
        else {
            puts("\nFile Not Found");
        }
    }
    free(fileCont);
    pthread_exit((void *)retVal);
}

void listDir() {
    DIR *dir;
    struct dirent *ent;
    dir = opendir(".");
    if (dir) {
        puts("");
        while ((ent = readdir(dir)) != NULL) {
            printf("%s\n", ent->d_name); 
        }
        puts("");
    }
    else {
        puts("Could not find library");
    }
    return;
}

void menu() {
    puts("Magical Music Machine");
    puts("0: Read a lyric file");
    puts("1: Choose a different file");
    puts("2: List library");
    puts("3: Show lyric file selected");
    puts("4: Exit");
    return;
}

int main() {
    int input;
    pthread_t threadNum;
    char buffer[0x20] = "flag.txt";
    chdir("./library");
    while(1) {
        menu();
        printf(">>> ");
        scanf("%d", &input);
        getchar();
        if (input >= 0 || input <= 4) {
            if (input == 0) {
                if (threadNum) {
                    pthread_join(threadNum, NULL);
                }
                pthread_create(&threadNum, NULL, (void *)readFile, (void *)buffer);
            }
            else if (input == 1) {
                printf("Enter the new lyric filename >>> ");
                fgets(buffer, 0x20, stdin);
                size_t len = strlen(buffer);
                buffer[len-1] = '\0';
            }
            else if (input == 2) {
                listDir();
            }
            else if (input == 3) {
                printf("\n%s\n\n", buffer);
            }
            else {
                return 0;
            }
        }
        else {
            puts("Invalid Option");
            return 0xff;
        }
    }
}