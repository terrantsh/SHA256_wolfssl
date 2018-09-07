#include <stdio.h>
#include "sha256.h"
#include <windows.h>

void  wc_Sha256GetHash(wc_Sha256* sha256, byte* hash);

int main() {
    char text [] = "78000100";
    wc_Sha256GetHash(wc_Sha256* text, byte* text);
    puts();
    return 0;
}