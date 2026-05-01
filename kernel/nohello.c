// SPDX-License-Identifier: GPL-2.0
//
// nohello - hide /data/nohello from all system calls
//
// Uses kprobes to intercept VFS operations and make the target file
// appear as non-existent. Identification uses (inode, dev) as the
// system-unique pair.
//
// Target: GKI kernels (android12-5.10 through android16-6.12)

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define TARGET_PATH "/data/nohello"
static dev_t target_dev;
static unsigned long long target_ino;

/* -- security_inode_permission -- open, access, chmod, chown, ... --------- */
static struct kretprobe kp_inode_perm;

struct inode_perm_data {
	unsigned long matched;
};

static int perm_inode_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;
	struct inode *inode;

	d->matched = 0;

#if defined(__aarch64__)
	inode = (struct inode *)regs->regs[0];
#elif defined(__x86_64__)
	inode = (struct inode *)regs->regs[0]; /* rdi */
#endif

	if (inode->i_ino == target_ino && inode->i_sb->s_dev == target_dev)
		d->matched = 1;

	return 0;
}

static int perm_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);

	return 0;
}

/* -- security_inode_getattr -- stat, statx, lstat ------------------------ */
static struct kretprobe kp_inode_getattr;

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;
	struct path *path;
	struct inode *inode;

	d->matched = 0;

#if defined(__aarch64__)
	path = (struct path *)regs->regs[0];	/* x0 */
#elif defined(__x86_64__)
	path = (struct path *)regs->regs[0];	/* rdi */
#endif

	inode = d_inode(path->dentry);
	if (inode && inode->i_ino == target_ino &&
	    inode->i_sb->s_dev == target_dev)
		d->matched = 1;

	return 0;
}

static int getattr_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);

	return 0;
}

/* -- __arm64_sys_getdents64 -- getdents / directory listing -------------- */
/*
 * On arm64 the getdents64 syscall handler is __arm64_sys_getdents64.
 * It takes a single const struct pt_regs * argument (the syscall registers).
 *
 * regs->regs[0] = fd    (from userspace x0)
 * regs->regs[1] = dirent (from userspace x1, the user buffer)
 * regs->regs[2] = count  (from userspace x2)
 *
 * Using a kretprobe on __arm64_sys_getdents64 (arm64-specific symbol) is
 * reliable because it is always the syscall entry point and always in
 * kallsyms on arm64 GKI kernels.
 */
static struct kretprobe kp_getdents;

struct getdents_cb_data {
	struct linux_dirent64 __user *dirent;
	void *kbuf;
};

/*
 * Entry: called in process context (GFP_KERNEL safe).
 * Extract the user buffer pointer from the nested pt_regs.
 * __arm64_sys_getdents64(const struct pt_regs *syscall_regs):
 *   x0 = struct pt_regs *  -->  regs->regs[0] is the syscall registers pointer
 *   user_regs->regs[1]     = the "dirent" buffer argument from userspace
 */
static int getdents_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	unsigned int count;

#if defined(__aarch64__)
	{
		struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
		d->dirent = (struct linux_dirent64 __user *)user_regs->regs[1];
		count = (unsigned int)user_regs->regs[2];
	}
#else
	/* On x86_64, __x64_sys_getdents64 takes fd, dirent, count directly */
	d->dirent = (struct linux_dirent64 __user *)regs->regs[1]; /* rsi */
	count = (unsigned int)regs->regs[2]; /* rdx */
#endif

	d->kbuf = kzalloc(count, GFP_KERNEL);

	return 0;
}

/*
 * Exit: called after the syscall returns.  The user buffer is already
 * filled with linux_dirent64 entries.  Walk the buffer, remove the
 * entry whose d_ino matches target_ino, and adjust the return value.
 */
static int getdents_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	long ret = regs->regs[0]; /* return value = bytes written */
	struct linux_dirent64 *kbuf, *src, *dst;
	long remain, new_len;
	const size_t hdr_off = offsetof(struct linux_dirent64, d_name);

	if (ret <= 0 || !d->dirent || !d->kbuf)
		goto out;

	if (copy_from_user(d->kbuf, d->dirent, ret))
		goto out;

	kbuf = d->kbuf;
	src = kbuf;
	dst = kbuf;
	remain = ret;

	while (remain > (long)hdr_off && src->d_reclen > 0 &&
	       remain >= (long)src->d_reclen) {

		if (src->d_ino == (__u64)target_ino) {
			/* Remove this entry: shift remaining data over it */
			long skip = src->d_reclen;
			long tail = remain - skip;
			if (tail > 0)
				memmove(dst, (char *)src + skip, tail);
			remain -= skip;
			src = (struct linux_dirent64 *)((char *)src + skip);
			continue;
		}

		if (dst != src)
			memmove(dst, src, src->d_reclen);
		dst = (struct linux_dirent64 *)((char *)dst + src->d_reclen);
		remain -= src->d_reclen;
		src = (struct linux_dirent64 *)((char *)src + src->d_reclen);
	}

	new_len = (long)((char *)dst - (char *)kbuf);

	if (new_len < ret &&
	    !copy_to_user(d->dirent, kbuf, new_len)) {
		regs->regs[0] = new_len;
	}

out:
	kfree(d->kbuf);
	d->kbuf = NULL;
	return 0;
}

/* -- Module init / exit -------------------------------------------------- */
static int __init nohello_init(void)
{
	struct path path;
	int ret;

	ret = kern_path(TARGET_PATH, 0, &path);
	if (ret) {
		pr_err("nohello: %s not found (err=%d)\n", TARGET_PATH, ret);
		return -ENOENT;
	}

	target_ino = d_inode(path.dentry)->i_ino;
	target_dev = d_inode(path.dentry)->i_sb->s_dev;
	pr_info("nohello: target ino=%llu dev=%u:%u\n",
		target_ino, MAJOR(target_dev), MINOR(target_dev));
	path_put(&path);

	/* -- kretprobe: security_inode_permission -- */
	kp_inode_perm.kp.symbol_name = "security_inode_permission";
	kp_inode_perm.entry_handler = perm_inode_entry;
	kp_inode_perm.handler = perm_exit;
	kp_inode_perm.data_size = sizeof(struct inode_perm_data);
	kp_inode_perm.maxactive = 40;
	ret = register_kretprobe(&kp_inode_perm);
	if (ret) {
		pr_err("nohello: register_kretprobe(security_inode_permission) "
		       "failed: %d\n", ret);
		return ret;
	}
	pr_info("nohello: hooked security_inode_permission\n");

	/* -- kretprobe: security_inode_getattr -- */
	kp_inode_getattr.kp.symbol_name = "security_inode_getattr";
	kp_inode_getattr.entry_handler = getattr_entry;
	kp_inode_getattr.handler = getattr_exit;
	kp_inode_getattr.data_size = sizeof(struct inode_perm_data);
	kp_inode_getattr.maxactive = 40;
	ret = register_kretprobe(&kp_inode_getattr);
	if (ret) {
		pr_err("nohello: register_kretprobe(security_inode_getattr) "
		       "failed: %d\n", ret);
		unregister_kretprobe(&kp_inode_perm);
		return ret;
	}
	pr_info("nohello: hooked security_inode_getattr\n");

	/* -- kretprobe: __arm64_sys_getdents64 -- */
	kp_getdents.kp.symbol_name = "__arm64_sys_getdents64";
	kp_getdents.entry_handler = getdents_entry;
	kp_getdents.handler = getdents_exit;
	kp_getdents.data_size = sizeof(struct getdents_cb_data);
	kp_getdents.maxactive = 20;
	ret = register_kretprobe(&kp_getdents);
	if (ret) {
		pr_warn("nohello: register_kretprobe(__arm64_sys_getdents64) "
			"failed: %d; file visible in listings but still "
			"hidden from direct access\n", ret);
	} else {
		pr_info("nohello: hooked __arm64_sys_getdents64\n");
	}

	pr_info("nohello: loaded -- %s is now hidden\n", TARGET_PATH);
	return 0;
}

static void __exit nohello_exit(void)
{
	unregister_kretprobe(&kp_inode_perm);
	unregister_kretprobe(&kp_inode_getattr);
	synchronize_rcu();

	unregister_kretprobe(&kp_getdents);

	pr_info("nohello: unloaded -- %s is visible again\n", TARGET_PATH);
}

module_init(nohello_init);
module_exit(nohello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lkm-build");
MODULE_DESCRIPTION("Hide /data/nohello by intercepting VFS operations via kprobes");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
