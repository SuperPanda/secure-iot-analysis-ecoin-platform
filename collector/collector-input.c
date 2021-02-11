/**
 * This is not my work. 
 *
 * This is a file sourced from:
 * https://github.com/troydhanson/misc/blob/master/network/unixdomain/cli.c
 *
 * It is included because it allows different shell scripts to attempt to pipe data to the program
 *  to different domain sockets if it is available.
 *  I.e. a script loops continuously and feeds data in every 5 seconds
 *  emulating an input. For example 1 script could get ping results and
 *  another could get packet loss, and they would automatically go
 *  to the relevant collector, or even the same collector.
 *
 *  If the collector is listening for that it will be written to the 
 *  socket.
 *
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

//char *socket_path = "./socket";
char *socket_path = "./socket-collector-Test";

int main(int argc, char *argv[]) {

  struct sockaddr_un addr;
  char buf[100];
  int fd,rc;

  if (argc > 1) socket_path=argv[1];

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("connect error");
    exit(-1);
  }
  while( (rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
 
    if (write(fd, buf, rc) != rc) {
      if (rc > 0) fprintf(stderr,"partial write");
      else {
        perror("write error");
        exit(-1);
      }
    }
  }

  return 0;
}