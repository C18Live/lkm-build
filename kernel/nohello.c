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

/* ── security_inode_permission — open, access, chmod, chown, … ──────────── */
static struct kretprobe kp_inode_perm;

struct inode_perm_data {
	unsigned long matched;
};

static int perm_inode_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = (struct inode_perm_data *)ri->data;
	struct inode *inode;

	d->matched = 0;

	/*
	 * arm64: x0 = inode, x1 = mask
	 * x86_64: rdi = inode, rsi = mask
	 */
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

/* ── security_inode_getattr — stat, statx, lstat ────────────────────────── */
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

/* ── ksys_getdents64 — getdents / directory listing ─────────────────────── */
/*
 * ksys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
 *                  unsigned int count)
 *
 * We allocate a temp buffer in the entry handler (process context, GFP_KERNEL)
 * and post-process it in the exit handler to remove the matching entry.
 *
 * arm64: x0=fd, x1=dirent, x2=count
 * x86_64: rdi=fd, rsi=dirent, rdx=count
 */
static struct kretprobe kp_getdents;

struct getdents_cb_data {
	struct linux_dirent64 __user *dirent;
	void *kbuf;
};

static int getdents_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	unsigned int count;

#if defined(__aarch64__)
	d->dirent = (struct linux_dirent64 __user *)regs->regs[1];
	count = (unsigned int)regs->regs[2];
#elif defined(__x86_64__)
	d->dirent = (struct linux_dirent64 __user *)regs->regs[1];
	count = (unsigned int)regs->regs[2];
#endif

	/* entry handler is process context, safe for GFP_KERNEL */
	d->kbuf = kzalloc(count, GFP_KERNEL);

	return 0;
}

static int getdents_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct getdents_cb_data *d = (struct getdents_cb_data *)ri->data;
	long ret = regs->regs[0];
	struct linux_dirent64 *src, *dst;
	long remain, new_len;
	const size_t hdr_off = offsetof(struct linux_dirent64, d_name);

	if (ret <= 0 || !d->dirent || !d->kbuf)
		goto out;

	if (copy_from_user(d->kbuf, d->dirent, ret))
		goto out;

	src = d->kbuf;
	dst = d->kbuf;
	remain = ret;

	while (remain > (long)hdr_off && src->d_reclen > 0 &&
	       remain >= (long)src->d_reclen) {

		if (src->d_ino == (__u64)target_ino) {
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

	new_len = (long)((char *)dst - (char *)d->kbuf);
	if (new_len < ret && !copy_to_user(d->dirent, d->kbuf, new_len))
		regs->regs[0] = new_len;

out:
	kfree(d->kbuf);
	d->kbuf = NULL;
	return 0;
}

/* ── Module init / exit ─────────────────────────────────────────────────── */
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

	/* ── kretprobe: security_inode_permission ── */
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

	/* ── kretprobe: security_inode_getattr ── */
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

	/* ── kretprobe: ksys_getdents64 (directory listing) ── */
	kp_getdents.kp.symbol_name = "ksys_getdents64";
	kp_getdents.entry_handler = getdents_entry;
	kp_getdents.handler = getdents_exit;
	kp_getdents.data_size = sizeof(struct getdents_cb_data);
	kp_getdents.maxactive = 20;
	ret = register_kretprobe(&kp_getdents);
	if (ret) {
		pr_warn("nohello: register_kretprobe(ksys_getdents64) "
			"failed: %d; file visible in listings but still "
			"hidden from direct access\n", ret);
	} else {
		pr_info("nohello: hooked ksys_getdents64\n");
	}

	pr_info("nohello: loaded — %s is now hidden\n", TARGET_PATH);
	return 0;
}

static void __exit nohello_exit(void)
{
	unregister_kretprobe(&kp_inode_perm);
	unregister_kretprobe(&kp_inode_getattr);
	synchronize_rcu();

	unregister_kretprobe(&kp_getdents);

	pr_info("nohello: unloaded — %s is visible again\n", TARGET_PATH);
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
