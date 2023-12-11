#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void ignore_me() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void gadgets() {
    asm("push 0x1; ret");
    asm("push 0xf; ret");
    asm("pop %rsi; ret;");
    asm("pop %rdi; ret;");
    asm("add %rcx, 0x31337; ret;");
    asm("push %r15; ret;");
    asm("pop %rax; ret;");
    asm("xchg %rsp, %rax; ret");
    asm("push 0x1337; ret");
    asm("syscall; ret");
    asm("xchg %rax, %rbx; ret;");
}


void logo() {
printf("\n--------------------------------------------------------------------------------");
printf("\n                                                                                ");
printf("\n                                                                          W00N  ");
printf("\n                                                                      WNKkoo0W  ");
printf("\n                                                                  WKko:'..dW    ");
printf("\n                                                               W0d;',:c. cN     ");
printf("\n                                                             Xx:.,lkXXl.:K      ");
printf("\n                                                           Xd,.:kX  K:.:K       ");
printf("\n                                                         Xx,.:OW  Nk'.lX        ");
printf("\n                                                    WN0xc'.'cxKWWO:.,kW         ");
printf("\n            WW                                   N0dc,...:OXXklo:.,xX           ");
printf("\n        NOo:;;:cloxO00xdK                    WXkl,,;c:;lOW  Wk' ,dX             ");
printf("\n      Nx,..cxxxol:;;,'..;loxk0KNW         WKd:,,cx0klo0W  WOc..lX               ");
printf("\n     K: 'dxdxON   WNX0Oxdlc:;,,;;:codkOOxo;,;lOXNO::kW  W0o;..lN                ");
printf("\n     Nx,.;kK0xdx0N         WWXK0kdoc:,..,:d0N WOloxdd0N0ood,.oN                 ");
printf("\n       Nk;.,dKN0xdx0W              WOoo0NW  W0olOW WOc:oOO;.oN                  ");
printf("\n         WO, .l0WXl;okKW         W0dd0W   WKolkN  NOdo0NO,.dN                   ");
printf("\n          Xl';'.:coOKkddkXW    W0dd0W   WXdlxN  Nkod0WWx''xW                    ");
printf("\n          WNNWXd,.;kN WKkddkXN0dd0W   XxlldX  XkodKW Nd.,OW                     ");
printf("\n                Nk;.,xX  WKdccd0W   NkldkKWWKxoxKW  Xl.:K                       ");
printf("\n                  NOc.'oKN0dd0W   WOoo0W WKdokX   W0;.cX                        ");
printf("\n                    W0:..cd0W   W0ooOWW0xdoON   W0dl'.oW                        ");
printf("\n                 WWNXx,.c0W   WKdlkNNOodxON   W0dd0Nd.,K                        ");
printf("\n     WX0Okxdollc::;,..cOOON  XxlxXXkod0W    W0dd0W  K,.xW                       ");
printf("\n   Xx:,;;::cclodxxc,:dxdoOWNklxKXxoxKW    W0dd0W    Wo :X                       ");
printf("\n  0;.cONWW     WO:.':dkKWNOod0KxoxX    WN0llOW       O..k                       ");
printf("\n K; 'ok0KXNW WO:. .coo0NOodOOdokN    W0doddokN       Nc cN                      ");
printf("\n Xxl:;,,,,,;:;..  cXNd,:okOdoONW00NW0ccONW XddX       k..O                      ");
printf("\n     WNXK0kxooxKx,.;,.,xkc:kW KdoOOc...lkKW Nko0W     X; ,oK                    ");
printf("\n                 Nkol,.',ldd0Oldkc.,x0o..'oX W0dxN    Wd. lN                    ");
printf("\n                     0' cXXo,':o; ,0  W0xc.'xNWk:lKW   K,.dW                    ");
printf("\n                     Nx,.,'. .oOc cN     WO:.,coOklkN  Wo ;K                    ");
printf("\n                       Xo. .c0WX;.dW       Nk,.cKWKodX  O..x                    ");
printf("\n                       X:.:0W  0'.O          Xc..oXNxlOWN: lN                   ");
printf("\n                       X;.xW   x.,K          No,,.,xXOlxO;.oW                   ");
printf("\n                       Wd.:X  Wo.cN           NNW0c.;kO:..:K                    ");
printf("\n                        0'.O  K;.xW               WO;...,xN                     ");
printf("\n                        Nl.lXO:.cX                  NklxN                       ");
printf("\n                         k..'';xN                                               ");
printf("\n                        /bin/sh\0                                               ");
printf("\n                                                                                ");
printf("\n--------------------------------------------------------------------------------");
printf("\n    the #GhostOfKyiv is alive, it embodies the collective spirit of the         ");
printf("\n           highly qualified pwn3rs - Volodymyr Zelenskyy                        ");
printf("\n--------------------------------------------------------------------------------");
//printf("\n  Pop RDI = %p, plt=0x401030, .text=%p, .rodata=0x402008",&gadgets+0x16,&gadgets);
//printf("\n--------------------------------------------------------------------------------");
}

void goodbye() {
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXOxxxkKWMMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMWNXXNWMMMMMMMMMMMMMMMMMMMNOdollol,     .lKMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMWX0d;...';:ldkOKXNWWMMWNWMMMWx.              lNMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMK;.            ..',;:c;,lllx0c              .dNMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMNo.                         .                .,lkNMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMX:                                              ;OWMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMX:                                               'xXNNXXXWMMMMMMMMMMMM");
	printf("\nMMMMMMMMW0:                                                  .''...:kNMMMMMMMMMM");
	printf("\nMMMMMMMXo.                                                           ,cdk0XNWMMM");
	printf("\nMMMMMWO;                                                                 ..';xNM");
	printf("\nMMMMMNc                                                                      oWM");
	printf("\nMMMMNd.                                                                     :XMM");
	printf("\nMMMMO.                                                                     .OMMM");
	printf("\nMMMMKl'.             ;dkOOkxl,.                                            '0MMM");
	printf("\nMMMMMWNX0xoc;...;oddkNMMMMMMMNO:.                                        ..;OMMM");
	printf("\nMMMMMMMMMMMMWNKXWMMMMMMMMMMMMMMWx.                                    'lk0KNWMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO'                                 .lXMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk.                            .,:lkNMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX0XK;   ':coxkc.            .'cdOXNWMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK;...  'xNWMMMMW0o;..      'o0NMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX:    .cKMMMMMMMMMMNOl.     lNMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMNl    ,xNMMMMMMMMMMXl.       .cOXNWMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMNkcclkXMMMMMMMMMMMMW0c.        .';dXMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNc  .,codxkO0XWMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXxdONMMMMMMMMMMMMMMMMMMMMMMMMM");
	printf("\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM");
}

int vuln() {
   int sz = 500;
   char s[23];
   logo();
   printf("\n The Ghost Welcomes You >>> ");
   gets(s);
}

int main() {
   vuln();
   printf("\n <<< Glory To The Ukraine.");
   goodbye();
}

