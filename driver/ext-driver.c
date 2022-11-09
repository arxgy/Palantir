#include <linux/mm.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/moduleparam.h>

#include "ext-ioctl.h"
#include "ext-driver.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ext_ioctl");
MODULE_AUTHOR("YGX");
MODULE_VERSION("0.1");


static int dev_open(struct inode *inodep, struct file *filep) {
  // filep->private_data = kvzalloc(sizeof(struct dev_private_data_t), GFP_KERNEL);

  // if(!filep->private_data)
  // {
  //   printk("dev_open: failed to allocate private_data\n");
  //   return -1;
  // }
  return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
  // if(filep->private_data)
  // {
  //   kvfree(filep->private_data);
  // }

  return 0;
}

static const struct file_operations ext_file_op = {
  // .open = dev_open,
  .owner = THIS_MODULE,
  .unlocked_ioctl = ext_ioctl,
  // .release = dev_release,
};

// rw_only
struct miscdevice ext_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "ext_dev",
  .fops = &ext_file_op,
  .mode = 0666,
};



static int __init ext_ioctl_init(void) {
  printk("hello world! ext_init\n");
  int ret;

  ret = misc_register(&ext_dev);
  if (ret < 0) {
    printk("failed to register ext_dev");
    goto deregister_dev;
  }
  printk("register success with minor number [%d]", ext_dev.minor);



  return 0;

deregister_dev:
  misc_deregister(&ext_dev);
  return ret;
}

static void __exit ext_ioctl_exit(void) {
  printk("bye world! ext_exit\n");
  misc_deregister(&ext_dev);
  printk("deregister success!\n");

}

module_init(ext_ioctl_init);
module_exit(ext_ioctl_exit);
