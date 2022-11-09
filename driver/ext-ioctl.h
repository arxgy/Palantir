#ifndef _EXT_IOCTL
#define _EXT_IOCTL
// frontend
#include <asm-generic/ioctl.h>

/*  not sure  */
#define EXT_IOC_MAGIC 0xee

long ext_ioctl(struct file* filep, unsigned int cmd, unsigned long args);

/*  DH channel  */ 
#define EXT_IOC_SEND_CHANNEL \ 
  _IOW(EXT_IOC_MAGIC, 0x00, struct ext_channel_param)

#define EXT_IOC_RECV_CHANNEL \ 
  _IOR(EXT_IOC_MAGIC, 0x01, struct ext_channel_param)


/*  send req to driver  */
#define EXT_IOC_SEND_REQUEST \ 
  _IOW(EXT_IOC_MAGIC, 0x02, struct ext_request_param)

/*  receive result from driver  */
#define EXT_IOC_RECV_REQUEST \
  _IOR(EXT_IOC_MAGIC, 0x03, struct ext_request_param)


struct ext_channel_param
{
  /* data */
  int data;
};

struct ext_request_param
{
  /* data */
  int data;
};





#endif