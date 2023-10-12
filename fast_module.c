#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <kvm/pvops.h>

static int sekvm_shmem_open(struct inode *inode, struct file *file)
{
	printk(KERN_ERR "sekvm_shmem file opened.\n");
	return 0;
}

static int sekvm_shmem_close(struct inode *inode, struct file *file)
{
	printk(KERN_ERR "sekvm_shmem file closed.\n");
	return 0;
}

static int sekvm_shmem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	printk(KERN_ERR "sekvm_shmem file mmaped.\n");
	return 0;
}

static struct file_operations fops =
{
	.owner		= THIS_MODULE,
	.open		= sekvm_shmem_open,
	.release	= sekvm_shmem_close,
	.mmap		= sekvm_shmem_mmap,
};

dev_t dev = 0;
static struct class *dev_class;
static struct cdev sekvm_shmem_cdev;

extern unsigned long long get_shmem_size_hypercall(void);

static int __init lkm_example_init(void)
{
	/* Allocating Major number */
	if ((alloc_chrdev_region(&dev, 0, 1, "sekvm_shmem")) < 0) {
		printk(KERN_INFO "sekvm_shmem_test: Cannot allocate major number.\n");
		return -1;
	}
	printk(KERN_INFO "sekvm_shmem_test: Major = %d Minor = %d \n", MAJOR(dev), MINOR(dev));

	/* Creating cdev structure */
	cdev_init(&sekvm_shmem_cdev, &fops);

	/* Adding character device to the system */
	if ((cdev_add(&sekvm_shmem_cdev, dev, 1)) < 0) {
		printk(KERN_INFO "sekvm_shmem_test: Cannot add the device to the system.\n");
		goto r_class;
	}

	/* Creating struct class */
	if ((dev_class = class_create(THIS_MODULE, "sekvm_shmem")) == NULL) {
		printk(KERN_INFO "sekvm_shmem_test: Cannot create the struct class.\n");
		goto r_class;
	}

	/* Creating device */
	if ((device_create(dev_class, NULL, dev, NULL, "sekvm_shmem_device")) == NULL) {
		printk(KERN_INFO "sekvm_shmem_test: Cannot create the Device 1\n");
		goto r_device;
	}

	printk(KERN_INFO "sekvm_shmem_test: installed.\n");
	
	printk(KERN_INFO "CALLING THE HYPERCALL\n");
	unsigned long long el2_shmem_region_size = get_shmem_size_hypercall();
	printk(KERN_INFO "WE CALLED THE HYPERCALL! AND WE GOT %llu BACK! \n", el2_shmem_region_size);
	return 0;

r_device:
	class_destroy(dev_class);
r_class:
	unregister_chrdev_region(dev,1);
	return -1;
}

static void __exit lkm_example_exit(void)
{
	printk("fast_module: Bye!");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
MODULE_LICENSE("GPL");
