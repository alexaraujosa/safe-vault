#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    execl("/bin/cat", "cat", argv[1], NULL);
    perror("execl failed");
    return 1;
}
