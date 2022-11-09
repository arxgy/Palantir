#include <linux/mm.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/moduleparam.h>
#include <asm/uaccess.h>
#include "ext-ioctl.h"

int ext_ioctl_send_channel(struct file *filep, unsigned long args) {
  struct ext_channel_param* param = (struct ext_channel_param*) args;
  printk("ext_ioctl_send_channel: %d\n", param->data);
  return 0;
}

int ext_ioctl_recv_channel(struct file *filep, unsigned long args) {
  struct ext_channel_param* param = (struct ext_channel_param*) args;
  printk("ext_ioctl_recv_channel: %d\n", param->data);

  return 0;
}

int ext_ioctl_send_request(struct file *filep, unsigned long args) {
  struct ext_request_param* param = (struct ext_request_param*) args;
  printk("ext_ioctl_send_request: %d\n", param->data);

  return 0;
}
int ext_ioctl_recv_request(struct file *filep, unsigned long args) {
  struct ext_request_param* param = (struct ext_request_param*) args;
  printk("ext_ioctl_recv_request: %d\n", param->data);

  return 0;
}

long ext_ioctl(struct file* filep, unsigned int cmd, unsigned long args) {
  int ret;
  char ioctl_param[1024];
  int ioc_size = _IOC_SIZE(cmd);
  
  if (ioc_size > sizeof(ioctl_param)) 
  {
    printk("ioctl_param buffer not enough\n");
    return -EFAULT;
  }
  
  if (copy_from_user(ioctl_param, (void *) args, ioc_size))
  {
    printk("copy_from_user failed\n");
    return -EFAULT;
  }
  
  switch (cmd)
  {
  case EXT_IOC_SEND_CHANNEL:
    ret = ext_ioctl_send_channel(filep, (unsigned long)ioctl_param);
    break;
  case EXT_IOC_RECV_CHANNEL:
    ret = ext_ioctl_recv_channel(filep, (unsigned long)ioctl_param);
    break;
  case EXT_IOC_SEND_REQUEST:
    ret = ext_ioctl_send_request(filep, (unsigned long)ioctl_param);
    break;
  case EXT_IOC_RECV_REQUEST:
    ret = ext_ioctl_recv_request(filep, (unsigned long)ioctl_param);
    break;

  default:
    printk("ioctl: cmd failed\n");
    ret = -EFAULT;
  }
  return ret;
}