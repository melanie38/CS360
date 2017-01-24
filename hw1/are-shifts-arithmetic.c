#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int int_shifts_are_arithmetic() {
    int x = ~0;
    return (x >> 1) < 0;
}

int main(int argc, char *argv[]) {
    int result = int_shifts_are_arithmetic();    
    printf("The right shift performed on this machine yielded a %d \n", result);
    return 0;
}
