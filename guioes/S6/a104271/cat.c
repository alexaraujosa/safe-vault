#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("Usage: ncat <file>\n");
    exit(0);
  }

  char* file = argv[1];
  // printf("FILE: %s\n", file);

  int fd = open(file, O_RDONLY);
  // printf("FD: %d\n", fd);

  struct stat buf;
  fstat(fd, &buf);
  off_t size = buf.st_size;

  char fbuf[size];

  if (read(fd, &fbuf, size) != size) {
    perror("Unable to read file");
  }

  // printf("BF: %s", fbuf);
  write(STDOUT_FILENO, &fbuf, size);

  return 0;
}
