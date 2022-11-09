#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "../driver/ext-ioctl.h"
int main() {
  int fd;
  fd = open("/dev/ext_dev", O_RDWR);
  if (fd < 0) {
    printf("error: %s", strerror(errno));
    return -1;
  }
  unsigned long nr_table[4] = {
    EXT_IOC_SEND_CHANNEL, EXT_IOC_RECV_CHANNEL, EXT_IOC_SEND_REQUEST, EXT_IOC_RECV_REQUEST
  };
  struct ext_channel_param param;
  param.data = 2077;
  for (size_t i = 0; i < 2; i++)
  {
    param.data = param.data+i;
    int ret = ioctl(fd, nr_table[i], &param);
    if (ret < 0)
    {
      printf("ioctl[%ld] failed: %s", i, strerror(errno));
    }
  }
  struct ext_request_param arg;
  arg.data = 3;
  for (size_t i = 2; i < 4; i++)
  {
    arg.data = arg.data+i;
    int ret = ioctl(fd, nr_table[i], &arg);
    if (ret < 0)
    {
      printf("ioctl[%ld] failed: %s", i, strerror(errno));
    }
  }

  close(fd);
  return 0;
}