#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

__attribute__((constructor)) void ignore_me()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

char army[5] = {'A', 'r', 'm', 'y', '\x00'};
char navy[5] = {'N', 'a', 'v', 'y', '\x00'};

void sing_navy()
{
	printf("Now colleges from sea to sea \n");
	printf("May sing of colors true, \n");
	printf("But who has better right than we \n");
	printf("To hoist a symbol hue: \n");
	printf("For sailors brave in battle fair \n");
	printf("Since fighting days of old, \n");
	printf("Have proved the sailor’s right to wear \n");
	printf("The Navy Blue & Gold. \n");
	printf("So hoist our colors, hoist them high, \n");
	printf("And vow allegiance true, \n");
	printf("So long as sunset gilds the sky \n");
	printf("Above the ocean blue, \n");
	printf("Unlowered shall those colors be \n");
	printf("Whatever fate they meet, \n");
	printf("So glorious in victory, \n");
	printf("Triumphant in defeat. \n");
	printf("Four years together by the Bay, \n");
	printf("Where Severn joins the tide, \n");
	printf("Then by the Service called away, \n");
	printf("We’re scattered far and wide; \n");
	printf("But still when two or three shall meet, \n");
	printf("And old tales be retold, \n");
	printf("From low to highest in the Fleet, \n");
	printf("We’ll pledge the Blue and Gold.\n");
}

void sing_army()
{
	printf("Hail, Alma Mater dear,\n");
	printf("To us be ever near,\n");
	printf("Help us thy motto bear\n");
	printf("Through all the years.\n");
	printf("Let duty be well performed,\n");
	printf("Honor be e'er untarned,\n");
	printf("Country be ever armed,\n");
	printf("West Point, by thee.\n");
	printf("Guide us, thy sons, aright,\n");
	printf("Teach us by day, by night,\n");
	printf("To keep thine honor bright,\n");
	printf("For thee to fight.\n");
	printf("When we depart from thee,\n");
	printf("Serving on land or sea,\n");
	printf("May we still loyal be,\n");
	printf("West Point, to thee.\n");
	printf("And when our work is done,\n");
	printf("Our course on earth is run,\n");
	printf("May it be said, 'Well Done;\n");
	printf("Be Thou At Peace.'\n");
	printf("E'er may that line of gray\n");
	printf("Increase from day to day,\n");
	printf("Live, serve, and die, we pray,\n");
	printf("West Point, for thee.\n");
}

void beat_team(char *team)
{
	printf("Beat %s!", team);
}

void vuln()
{
	char overflow[8];
	printf("\nTell me how the game ends >>> ");
	read(0, &overflow, 256);
}

int main()
{
	vuln();
	return 0;
}

void easy_button() {
    __asm__(
"        ldp x0, x1, [sp], #0x10 \n" 
"        ldp x29, x30, [sp], #0x10 \n" 
"        ret \n"
    );
}

