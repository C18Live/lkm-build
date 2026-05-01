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
#define MAX_GETDENTS_BUF (16 * 1024)

static dev_t target_dev;
static unsigned long long target_ino; /* filldir64 passes u64 ino */

/* ── security_inode_permission — open, access, chmod, chown, … ──────────── */
static struct kretprobe kp_inode_perm;

struct inode_perm_data {
	unsigned long matched;
};

static int perm_inode_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = ri->data;
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
	struct inode_perm_data *d = ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);

	return 0;
}

/* ── security_inode_getattr — stat, statx, lstat ────────────────────────── */
static struct kretprobe kp_inode_getattr;

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct inode_perm_data *d = ri->data;
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
	struct inode_perm_data *d = ri->data;

	if (d->matched)
		regs_set_return_value(regs, -ENOENT);

	return 0;
}

/* ── filldir64 — getdents / directory listing ──────────────────────────── */
/*
 * filldir64(struct dir_context *ctx, const char *name, int namelen,
 *           loff_t offset, u64 ino, unsigned int d_type)
 *
 * With KPROBE_FTRACE (default on GKI), returning 1 from pre_handler
 * entirely skips the function, so the entry is never added.
 *
 * arm64: x0=ctx, x1=name, x2=namelen, x3=offset, x4=ino, x5=d_type
 * x86_64: rdi=ctx, rsi=name, rdx=namelen, rcx=offset, r8=ino, r9=d_type
 */
static struct kprobe kp_filldir;

static int filldir_pre(struct kprobe *p, struct pt_regs *regs)
{
	u64 ino;

#if defined(__aarch64__)
	ino = regs->regs[4];
#elif defined(__x86_64__)
	ino = regs->regs[8];
#else
	return 0;
#endif

	if (ino == (u64)target_ino) {
		regs_set_return_value(regs, 0);
		return 1;	/* skip the entire function */
	}

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

	/* ── kprobe: filldir64 (directory listing, non-fatal if fails) ── */
	kp_filldir.symbol_name = "filldir64";
	kp_filldir.pre_handler = filldir_pre;
	ret = register_kprobe(&kp_filldir);
	if (ret) {
		pr_warn("nohello: cannot kprobe filldir64 (%d); "
			"file visible in listings but still hidden from "
			"direct access\n", ret);
	} else {
		pr_info("nohello: hooked filldir64\n");
	}

	pr_info("nohello: loaded — %s is now hidden\n", TARGET_PATH);
	return 0;
}

static void __exit nohello_exit(void)
{
	unregister_kretprobe(&kp_inode_perm);
	unregister_kretprobe(&kp_inode_getattr);
	synchronize_rcu();

	if (kp_filldir.symbol_name) {
		unregister_kprobe(&kp_filldir);
		kp_filldir.symbol_name = NULL;
	}

	pr_info("nohello: unloaded — %s is visible again\n", TARGET_PATH);
}

module_init(nohello_init);
module_exit(nohello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lkm-build");
MODULE_DESCRIPTION("Hide /data/nohello by intercepting VFS operations via kprobes");
