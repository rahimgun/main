/**
 * @file lkm_example.c
 * @brief 
 * @version 0.1
 * @date 2021-08-27
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Write random number to dmesg");

/**
 * 
 * @brief generate random number and write to kernel buffer when loaded
 * 
 * @return int 
 * @retval 0: on success
 */
static int __init lkm_example_init(void)
{
	int rand = 0;
	get_random_bytes(&rand, sizeof(int));
    printk(KERN_INFO "lkm_example_rand_number %d\n", rand);
    return 0;
}
/**
 * @brief print Goodbye, World to kernel buffer when unloaded
 * 
 */
static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "Goodbye, World\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
