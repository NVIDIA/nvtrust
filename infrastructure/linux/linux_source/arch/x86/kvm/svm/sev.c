// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM-SEV support
 *
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 */

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/psp-sev.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/misc_cgroup.h>
#include <linux/processor.h>
#include <linux/trace_events.h>
#include <linux/hugetlb.h>
#include <linux/sev.h>
#include <linux/ksm.h>

#include <asm/pkru.h>
#include <asm/trapnr.h>
#include <asm/fpu/xcr.h>
#include <asm/sev.h>
#include <asm/mman.h>

#include "mmu.h"
#include "x86.h"
#include "svm.h"
#include "svm_ops.h"
#include "cpuid.h"
#include "trace.h"
#include "mmu.h"

#ifndef CONFIG_KVM_AMD_SEV
/*
 * When this config is not defined, SEV feature is not supported and APIs in
 * this file are not used but this file still gets compiled into the KVM AMD
 * module.
 *
 * We will not have MISC_CG_RES_SEV and MISC_CG_RES_SEV_ES entries in the enum
 * misc_res_type {} defined in linux/misc_cgroup.h.
 *
 * Below macros allow compilation to succeed.
 */
#define MISC_CG_RES_SEV MISC_CG_RES_TYPES
#define MISC_CG_RES_SEV_ES MISC_CG_RES_TYPES
#endif

#ifdef CONFIG_KVM_AMD_SEV
/* enable/disable SEV support */
static bool sev_enabled = true;
module_param_named(sev, sev_enabled, bool, 0444);

/* enable/disable SEV-ES support */
static bool sev_es_enabled = true;
module_param_named(sev_es, sev_es_enabled, bool, 0444);

/* enable/disable SEV-SNP support */
static bool sev_snp_enabled = true;
module_param_named(sev_snp, sev_snp_enabled, bool, 0444);
#else
#define sev_enabled false
#define sev_es_enabled false
#endif /* CONFIG_KVM_AMD_SEV */

#define AP_RESET_HOLD_NONE		0
#define AP_RESET_HOLD_NAE_EVENT		1
#define AP_RESET_HOLD_MSR_PROTO		2

static u8 sev_enc_bit;
static DECLARE_RWSEM(sev_deactivate_lock);
static DEFINE_MUTEX(sev_bitmap_lock);
unsigned int max_sev_asid;
static unsigned int min_sev_asid;
static unsigned long sev_me_mask;
static unsigned int nr_asids;
static unsigned long *sev_asid_bitmap;
static unsigned long *sev_reclaim_asid_bitmap;

static int snp_decommission_context(struct kvm *kvm);

struct enc_region {
	struct list_head list;
	unsigned long npages;
	struct page **pages;
	unsigned long uaddr;
	unsigned long size;
};

/* Called with the sev_bitmap_lock held, or on shutdown  */
static int sev_flush_asids(int min_asid, int max_asid)
{
	int ret, asid, error = 0;

	/* Check if there are any ASIDs to reclaim before performing a flush */
	asid = find_next_bit(sev_reclaim_asid_bitmap, nr_asids, min_asid);
	if (asid > max_asid)
		return -EBUSY;

	/*
	 * DEACTIVATE will clear the WBINVD indicator causing DF_FLUSH to fail,
	 * so it must be guarded.
	 */
	down_write(&sev_deactivate_lock);

	wbinvd_on_all_cpus();

	if (sev_snp_enabled)
		ret = snp_guest_df_flush(&error);
	else
		ret = sev_guest_df_flush(&error);

	up_write(&sev_deactivate_lock);

	if (ret)
		pr_err("SEV%s: DF_FLUSH failed, ret=%d, error=%#x\n",
			sev_snp_enabled ? "-SNP" : "", ret, error);

	return ret;
}

static inline bool is_mirroring_enc_context(struct kvm *kvm)
{
	return !!to_kvm_svm(kvm)->sev_info.enc_context_owner;
}

/* Must be called with the sev_bitmap_lock held */
static bool __sev_recycle_asids(int min_asid, int max_asid)
{
	if (sev_flush_asids(min_asid, max_asid))
		return false;

	/* The flush process will flush all reclaimable SEV and SEV-ES ASIDs */
	bitmap_xor(sev_asid_bitmap, sev_asid_bitmap, sev_reclaim_asid_bitmap,
		   nr_asids);
	bitmap_zero(sev_reclaim_asid_bitmap, nr_asids);

	return true;
}

static int sev_misc_cg_try_charge(struct kvm_sev_info *sev)
{
	enum misc_res_type type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
	return misc_cg_try_charge(type, sev->misc_cg, 1);
}

static void sev_misc_cg_uncharge(struct kvm_sev_info *sev)
{
	enum misc_res_type type = sev->es_active ? MISC_CG_RES_SEV_ES : MISC_CG_RES_SEV;
	misc_cg_uncharge(type, sev->misc_cg, 1);
}

static int sev_asid_new(struct kvm_sev_info *sev)
{
	int asid, min_asid, max_asid, ret;
	bool retry = true;

	WARN_ON(sev->misc_cg);
	sev->misc_cg = get_current_misc_cg();
	ret = sev_misc_cg_try_charge(sev);
	if (ret) {
		put_misc_cg(sev->misc_cg);
		sev->misc_cg = NULL;
		return ret;
	}

	mutex_lock(&sev_bitmap_lock);

	/*
	 * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
	 * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
	 */
	min_asid = sev->es_active ? 1 : min_sev_asid;
	max_asid = sev->es_active ? min_sev_asid - 1 : max_sev_asid;
again:
	asid = find_next_zero_bit(sev_asid_bitmap, max_asid + 1, min_asid);
	if (asid > max_asid) {
		if (retry && __sev_recycle_asids(min_asid, max_asid)) {
			retry = false;
			goto again;
		}
		mutex_unlock(&sev_bitmap_lock);
		ret = -EBUSY;
		goto e_uncharge;
	}

	__set_bit(asid, sev_asid_bitmap);

	mutex_unlock(&sev_bitmap_lock);

	return asid;
e_uncharge:
	sev_misc_cg_uncharge(sev);
	put_misc_cg(sev->misc_cg);
	sev->misc_cg = NULL;
	return ret;
}

static int sev_get_asid(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->asid;
}

static void sev_asid_free(struct kvm_sev_info *sev)
{
	struct svm_cpu_data *sd;
	int cpu;

	mutex_lock(&sev_bitmap_lock);

	__set_bit(sev->asid, sev_reclaim_asid_bitmap);

	for_each_possible_cpu(cpu) {
		sd = per_cpu(svm_data, cpu);
		sd->sev_vmcbs[sev->asid] = NULL;
	}

	mutex_unlock(&sev_bitmap_lock);

	sev_misc_cg_uncharge(sev);
	put_misc_cg(sev->misc_cg);
	sev->misc_cg = NULL;
}

static void sev_decommission(unsigned int handle)
{
	struct sev_data_decommission decommission;

	if (!handle)
		return;

	decommission.handle = handle;
	sev_guest_decommission(&decommission, NULL);
}

static inline void snp_leak_pages(u64 pfn, enum pg_level level)
{
	unsigned int npages = page_level_size(level) >> PAGE_SHIFT;

	WARN(1, "psc failed pfn 0x%llx pages %d (leaking)\n", pfn, npages);

	while (npages) {
		memory_failure(pfn, 0);
		dump_rmpentry(pfn);
		npages--;
		pfn++;
	}
}

static int snp_page_reclaim(u64 pfn)
{
	struct sev_data_snp_page_reclaim data = {0};
	int err, rc;

	data.paddr = __sme_set(pfn << PAGE_SHIFT);
	rc = snp_guest_page_reclaim(&data, &err);
	if (rc) {
		/*
		 * If the reclaim failed, then page is no longer safe
		 * to use.
		 */
		snp_leak_pages(pfn, PG_LEVEL_4K);
	}

	return rc;
}

static int host_rmp_make_shared(u64 pfn, enum pg_level level, bool leak)
{
	int rc;

	rc = rmp_make_shared(pfn, level);
	if (rc && leak)
		snp_leak_pages(pfn, level);

	return rc;
}

static void sev_unbind_asid(struct kvm *kvm, unsigned int handle)
{
	struct sev_data_deactivate deactivate;

	if (!handle)
		return;

	deactivate.handle = handle;

	/* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
	down_read(&sev_deactivate_lock);
	sev_guest_deactivate(&deactivate, NULL);
	up_read(&sev_deactivate_lock);

	sev_decommission(handle);
}

static int verify_snp_init_flags(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_snp_init params;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	if (params.flags & ~SEV_SNP_SUPPORTED_FLAGS)
		ret = -EOPNOTSUPP;

	params.flags = SEV_SNP_SUPPORTED_FLAGS;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params)))
		ret = -EFAULT;

	return ret;
}

static int sev_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	int asid, ret;

	if (kvm->created_vcpus)
		return -EINVAL;

	ret = -EBUSY;
	if (unlikely(sev->active))
		return ret;

	sev->active = true;
	sev->es_active = (argp->id == KVM_SEV_ES_INIT || argp->id == KVM_SEV_SNP_INIT);
	sev->snp_active = argp->id == KVM_SEV_SNP_INIT;
	asid = sev_asid_new(sev);
	if (asid < 0)
		goto e_no_asid;
	sev->asid = asid;

	if (sev->snp_active) {
		ret = verify_snp_init_flags(kvm, argp);
		if (ret)
			goto e_free;

		spin_lock_init(&sev->psc_lock);
		ret = sev_snp_init(&argp->error);
		mutex_init(&sev->guest_req_lock);
	} else {
		ret = sev_platform_init(&argp->error);
	}

	if (ret)
		goto e_free;

	INIT_LIST_HEAD(&sev->regions_list);
	INIT_LIST_HEAD(&sev->mirror_vms);

	kvm_set_apicv_inhibit(kvm, APICV_INHIBIT_REASON_SEV);

	return 0;

e_free:
	sev_asid_free(sev);
	sev->asid = 0;
e_no_asid:
	sev->snp_active = false;
	sev->es_active = false;
	sev->active = false;
	return ret;
}

static int sev_bind_asid(struct kvm *kvm, unsigned int handle, int *error)
{
	struct sev_data_activate activate;
	int asid = sev_get_asid(kvm);
	int ret;

	/* activate ASID on the given handle */
	activate.handle = handle;
	activate.asid   = asid;
	ret = sev_guest_activate(&activate, error);

	return ret;
}

static int __sev_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int sev_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __sev_issue_cmd(sev->fd, id, data, error);
}

static int sev_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_start start;
	struct kvm_sev_launch_start params;
	void *dh_blob, *session_blob;
	int *error = &argp->error;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	memset(&start, 0, sizeof(start));

	dh_blob = NULL;
	if (params.dh_uaddr) {
		dh_blob = psp_copy_user_blob(params.dh_uaddr, params.dh_len);
		if (IS_ERR(dh_blob))
			return PTR_ERR(dh_blob);

		start.dh_cert_address = __sme_set(__pa(dh_blob));
		start.dh_cert_len = params.dh_len;
	}

	session_blob = NULL;
	if (params.session_uaddr) {
		session_blob = psp_copy_user_blob(params.session_uaddr, params.session_len);
		if (IS_ERR(session_blob)) {
			ret = PTR_ERR(session_blob);
			goto e_free_dh;
		}

		start.session_address = __sme_set(__pa(session_blob));
		start.session_len = params.session_len;
	}

	start.handle = params.handle;
	start.policy = params.policy;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_LAUNCH_START, &start, error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start.handle, error);
	if (ret) {
		sev_decommission(start.handle);
		goto e_free_session;
	}

	/* return handle to userspace */
	params.handle = start.handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params))) {
		sev_unbind_asid(kvm, start.handle);
		ret = -EFAULT;
		goto e_free_session;
	}

	sev->handle = start.handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_blob);
e_free_dh:
	kfree(dh_blob);
	return ret;
}

static struct page **sev_pin_memory(struct kvm *kvm, unsigned long uaddr,
				    unsigned long ulen, unsigned long *n,
				    int write)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	unsigned long npages, size;
	int npinned;
	unsigned long locked, lock_limit;
	struct page **pages;
	unsigned long first, last;
	int ret;

	lockdep_assert_held(&kvm->lock);

	if (ulen == 0 || uaddr + ulen < uaddr)
		return ERR_PTR(-EINVAL);

	/* Calculate number of pages. */
	first = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last = ((uaddr + ulen - 1) & PAGE_MASK) >> PAGE_SHIFT;
	npages = (last - first + 1);

	locked = sev->pages_locked + npages;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_err("SEV: %lu locked pages exceed the lock limit of %lu.\n", locked, lock_limit);
		return ERR_PTR(-ENOMEM);
	}

	if (WARN_ON_ONCE(npages > INT_MAX))
		return ERR_PTR(-EINVAL);

	/* Avoid using vmalloc for smaller buffers. */
	size = npages * sizeof(struct page *);
	if (size > PAGE_SIZE)
		pages = __vmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	else
		pages = kmalloc(size, GFP_KERNEL_ACCOUNT);

	if (!pages)
		return ERR_PTR(-ENOMEM);

	/* Pin the user virtual address. */
	npinned = pin_user_pages_fast(uaddr, npages, write ? FOLL_WRITE : 0, pages);
	if (npinned != npages) {
		pr_err("SEV: Failure locking %lu pages.\n", npages);
		ret = -ENOMEM;
		goto err;
	}

	*n = npages;
	sev->pages_locked = locked;

	return pages;

err:
	if (npinned > 0)
		unpin_user_pages(pages, npinned);

	kvfree(pages);
	return ERR_PTR(ret);
}

static void sev_unpin_memory(struct kvm *kvm, struct page **pages,
			     unsigned long npages)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	unpin_user_pages(pages, npages);
	kvfree(pages);
	sev->pages_locked -= npages;
}

static void sev_clflush_pages(struct page *pages[], unsigned long npages)
{
	uint8_t *page_virtual;
	unsigned long i;

	if (this_cpu_has(X86_FEATURE_SME_COHERENT) || npages == 0 ||
	    pages == NULL)
		return;

	for (i = 0; i < npages; i++) {
		page_virtual = kmap_atomic(pages[i]);
		clflush_cache_range(page_virtual, PAGE_SIZE);
		kunmap_atomic(page_virtual);
		cond_resched();
	}
}

static unsigned long get_num_contig_pages(unsigned long idx,
				struct page **inpages, unsigned long npages)
{
	unsigned long paddr, next_paddr;
	unsigned long i = idx + 1, pages = 1;

	/* find the number of contiguous pages starting from idx */
	paddr = __sme_page_pa(inpages[idx]);
	while (i < npages) {
		next_paddr = __sme_page_pa(inpages[i++]);
		if ((paddr + PAGE_SIZE) == next_paddr) {
			pages++;
			paddr = next_paddr;
			continue;
		}
		break;
	}

	return pages;
}

static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long vaddr, vaddr_end, next_vaddr, npages, pages, size, i;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_launch_update_data params;
	struct sev_data_launch_update_data data;
	struct page **inpages;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	vaddr = params.uaddr;
	size = params.len;
	vaddr_end = vaddr + size;

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, vaddr, size, &npages, 1);
	if (IS_ERR(inpages))
		return PTR_ERR(inpages);

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_UPDATE encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(inpages, npages);

	data.reserved = 0;
	data.handle = sev->handle;

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i += pages) {
		int offset, len;

		/*
		 * If the user buffer is not page-aligned, calculate the offset
		 * within the page.
		 */
		offset = vaddr & (PAGE_SIZE - 1);

		/* Calculate the number of pages that can be encrypted in one go. */
		pages = get_num_contig_pages(i, inpages, npages);

		len = min_t(size_t, ((pages * PAGE_SIZE) - offset), size);

		data.len = len;
		data.address = __sme_page_pa(inpages[i]) + offset;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_DATA, &data, &argp->error);
		if (ret)
			goto e_unpin;

		size -= len;
		next_vaddr = vaddr + len;
	}

e_unpin:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);
	}
	/* unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);
	return ret;
}

static int sev_es_sync_vmsa(struct vcpu_svm *svm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;
	struct sev_es_save_area *save = svm->sev_es.vmsa;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (svm->vmcb->save.dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/*
	 * SEV-ES will use a VMSA that is pointed to by the VMCB, not
	 * the traditional VMSA that is part of the VMCB. Copy the
	 * traditional VMSA as it has been built so far (in prep
	 * for LAUNCH_UPDATE_VMSA) to be the initial SEV-ES state.
	 */
	memcpy(save, &svm->vmcb->save, sizeof(svm->vmcb->save));

	/* Sync registgers */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rbx = svm->vcpu.arch.regs[VCPU_REGS_RBX];
	save->rcx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rsp = svm->vcpu.arch.regs[VCPU_REGS_RSP];
	save->rbp = svm->vcpu.arch.regs[VCPU_REGS_RBP];
	save->rsi = svm->vcpu.arch.regs[VCPU_REGS_RSI];
	save->rdi = svm->vcpu.arch.regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
	save->r8  = svm->vcpu.arch.regs[VCPU_REGS_R8];
	save->r9  = svm->vcpu.arch.regs[VCPU_REGS_R9];
	save->r10 = svm->vcpu.arch.regs[VCPU_REGS_R10];
	save->r11 = svm->vcpu.arch.regs[VCPU_REGS_R11];
	save->r12 = svm->vcpu.arch.regs[VCPU_REGS_R12];
	save->r13 = svm->vcpu.arch.regs[VCPU_REGS_R13];
	save->r14 = svm->vcpu.arch.regs[VCPU_REGS_R14];
	save->r15 = svm->vcpu.arch.regs[VCPU_REGS_R15];
#endif
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];

	/* Sync some non-GPR registers before encrypting */
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->pkru = svm->vcpu.arch.pkru;
	save->xss  = svm->vcpu.arch.ia32_xss;
	save->dr6  = svm->vcpu.arch.dr6;

	/* Enable the SEV-SNP feature */
	if (sev_snp_guest(svm->vcpu.kvm))
		save->sev_features |= SVM_SEV_FEAT_SNP_ACTIVE;

	/*
	 * Save the VMSA synced SEV features. For now, they are the same for
	 * all vCPUs, so just save each time.
	 */
	sev->sev_features = save->sev_features;

	return 0;
}

static int __sev_launch_update_vmsa(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    int *error)
{
	struct sev_data_launch_update_vmsa vmsa;
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	/* Perform some pre-encryption checks against the VMSA */
	ret = sev_es_sync_vmsa(svm);
	if (ret)
		return ret;

	/*
	 * The LAUNCH_UPDATE_VMSA command will perform in-place encryption of
	 * the VMSA memory content (i.e it will write the same memory region
	 * with the guest's key), so invalidate it first.
	 */
	clflush_cache_range(svm->sev_es.vmsa, PAGE_SIZE);

	vmsa.reserved = 0;
	vmsa.handle = to_kvm_svm(kvm)->sev_info.handle;
	vmsa.address = __sme_pa(svm->sev_es.vmsa);
	vmsa.len = PAGE_SIZE;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_VMSA, &vmsa, error);
	if (ret)
	  return ret;

	vcpu->arch.guest_state_protected = true;
	return 0;
}

static int sev_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = mutex_lock_killable(&vcpu->mutex);
		if (ret)
			return ret;

		ret = __sev_launch_update_vmsa(kvm, vcpu, &argp->error);

		mutex_unlock(&vcpu->mutex);
		if (ret)
			return ret;
	}

	return 0;
}

static int sev_launch_measure(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *measure = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_measure data;
	struct kvm_sev_launch_measure params;
	void __user *p = NULL;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, measure, sizeof(params)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE)
			return -EINVAL;

		blob = kzalloc(params.len, GFP_KERNEL_ACCOUNT);
		if (!blob)
			return -ENOMEM;

		data.address = __psp_pa(blob);
		data.len = params.len;
	}

cmd:
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_MEASURE, &data, &argp->error);

	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data.len;
	if (copy_to_user(measure, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
	return ret;
}

static int sev_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_LAUNCH_FINISH, &data, &argp->error);
}

static int sev_guest_status(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_guest_status params;
	struct sev_data_guest_status data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	memset(&data, 0, sizeof(data));

	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_GUEST_STATUS, &data, &argp->error);
	if (ret)
		return ret;

	params.policy = data.policy;
	params.state = data.state;
	params.handle = data.handle;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params)))
		ret = -EFAULT;

	return ret;
}

static int __sev_issue_dbg_cmd(struct kvm *kvm, unsigned long src,
			       unsigned long dst, int size,
			       int *error, bool enc)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_dbg data;

	data.reserved = 0;
	data.handle = sev->handle;
	data.dst_addr = dst;
	data.src_addr = src;
	data.len = size;

	return sev_issue_cmd(kvm,
			     enc ? SEV_CMD_DBG_ENCRYPT : SEV_CMD_DBG_DECRYPT,
			     &data, error);
}

static int __sev_dbg_decrypt(struct kvm *kvm, unsigned long src_paddr,
			     unsigned long dst_paddr, int sz, int *err)
{
	int offset;

	/*
	 * Its safe to read more than we are asked, caller should ensure that
	 * destination has enough space.
	 */
	offset = src_paddr & 15;
	src_paddr = round_down(src_paddr, 16);
	sz = round_up(sz + offset, 16);

	return __sev_issue_dbg_cmd(kvm, src_paddr, dst_paddr, sz, err, false);
}

static int __sev_dbg_decrypt_user(struct kvm *kvm, unsigned long paddr,
				  void __user *dst_uaddr,
				  unsigned long dst_paddr,
				  int size, int *err)
{
	struct page *tpage = NULL;
	int ret, offset;

	/* if inputs are not 16-byte then use intermediate buffer */
	if (!IS_ALIGNED(dst_paddr, 16) ||
	    !IS_ALIGNED(paddr,     16) ||
	    !IS_ALIGNED(size,      16)) {
		tpage = (void *)alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!tpage)
			return -ENOMEM;

		dst_paddr = __sme_page_pa(tpage);
	}

	ret = __sev_dbg_decrypt(kvm, paddr, dst_paddr, size, err);
	if (ret)
		goto e_free;

	if (tpage) {
		offset = paddr & 15;
		if (copy_to_user(dst_uaddr, page_address(tpage) + offset, size))
			ret = -EFAULT;
	}

e_free:
	if (tpage)
		__free_page(tpage);

	return ret;
}

static int __sev_dbg_encrypt_user(struct kvm *kvm, unsigned long paddr,
				  void __user *vaddr,
				  unsigned long dst_paddr,
				  void __user *dst_vaddr,
				  int size, int *error)
{
	struct page *src_tpage = NULL;
	struct page *dst_tpage = NULL;
	int ret, len = size;

	/* If source buffer is not aligned then use an intermediate buffer */
	if (!IS_ALIGNED((unsigned long)vaddr, 16)) {
		src_tpage = alloc_page(GFP_KERNEL_ACCOUNT);
		if (!src_tpage)
			return -ENOMEM;

		if (copy_from_user(page_address(src_tpage), vaddr, size)) {
			__free_page(src_tpage);
			return -EFAULT;
		}

		paddr = __sme_page_pa(src_tpage);
	}

	/*
	 *  If destination buffer or length is not aligned then do read-modify-write:
	 *   - decrypt destination in an intermediate buffer
	 *   - copy the source buffer in an intermediate buffer
	 *   - use the intermediate buffer as source buffer
	 */
	if (!IS_ALIGNED((unsigned long)dst_vaddr, 16) || !IS_ALIGNED(size, 16)) {
		int dst_offset;

		dst_tpage = alloc_page(GFP_KERNEL_ACCOUNT);
		if (!dst_tpage) {
			ret = -ENOMEM;
			goto e_free;
		}

		ret = __sev_dbg_decrypt(kvm, dst_paddr,
					__sme_page_pa(dst_tpage), size, error);
		if (ret)
			goto e_free;

		/*
		 *  If source is kernel buffer then use memcpy() otherwise
		 *  copy_from_user().
		 */
		dst_offset = dst_paddr & 15;

		if (src_tpage)
			memcpy(page_address(dst_tpage) + dst_offset,
			       page_address(src_tpage), size);
		else {
			if (copy_from_user(page_address(dst_tpage) + dst_offset,
					   vaddr, size)) {
				ret = -EFAULT;
				goto e_free;
			}
		}

		paddr = __sme_page_pa(dst_tpage);
		dst_paddr = round_down(dst_paddr, 16);
		len = round_up(size, 16);
	}

	ret = __sev_issue_dbg_cmd(kvm, paddr, dst_paddr, len, error, true);

e_free:
	if (src_tpage)
		__free_page(src_tpage);
	if (dst_tpage)
		__free_page(dst_tpage);
	return ret;
}

static int sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec)
{
	unsigned long vaddr, vaddr_end, next_vaddr;
	unsigned long dst_vaddr;
	struct page **src_p, **dst_p;
	struct kvm_sev_dbg debug;
	unsigned long n;
	unsigned int size;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&debug, (void __user *)(uintptr_t)argp->data, sizeof(debug)))
		return -EFAULT;

	if (!debug.len || debug.src_uaddr + debug.len < debug.src_uaddr)
		return -EINVAL;
	if (!debug.dst_uaddr)
		return -EINVAL;

	vaddr = debug.src_uaddr;
	size = debug.len;
	vaddr_end = vaddr + size;
	dst_vaddr = debug.dst_uaddr;

	for (; vaddr < vaddr_end; vaddr = next_vaddr) {
		int len, s_off, d_off;

		/* lock userspace source and destination page */
		src_p = sev_pin_memory(kvm, vaddr & PAGE_MASK, PAGE_SIZE, &n, 0);
		if (IS_ERR(src_p))
			return PTR_ERR(src_p);

		dst_p = sev_pin_memory(kvm, dst_vaddr & PAGE_MASK, PAGE_SIZE, &n, 1);
		if (IS_ERR(dst_p)) {
			sev_unpin_memory(kvm, src_p, n);
			return PTR_ERR(dst_p);
		}

		/*
		 * Flush (on non-coherent CPUs) before DBG_{DE,EN}CRYPT read or modify
		 * the pages; flush the destination too so that future accesses do not
		 * see stale data.
		 */
		sev_clflush_pages(src_p, 1);
		sev_clflush_pages(dst_p, 1);

		/*
		 * Since user buffer may not be page aligned, calculate the
		 * offset within the page.
		 */
		s_off = vaddr & ~PAGE_MASK;
		d_off = dst_vaddr & ~PAGE_MASK;
		len = min_t(size_t, (PAGE_SIZE - s_off), size);

		if (dec)
			ret = __sev_dbg_decrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     (void __user *)dst_vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     len, &argp->error);
		else
			ret = __sev_dbg_encrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     (void __user *)vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     (void __user *)dst_vaddr,
						     len, &argp->error);

		sev_unpin_memory(kvm, src_p, n);
		sev_unpin_memory(kvm, dst_p, n);

		if (ret)
			goto err;

		next_vaddr = vaddr + len;
		dst_vaddr = dst_vaddr + len;
		size -= len;
	}
err:
	return ret;
}

static int sev_launch_secret(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_secret data;
	struct kvm_sev_launch_secret params;
	struct page **pages;
	void *blob, *hdr;
	unsigned long n, i;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	pages = sev_pin_memory(kvm, params.guest_uaddr, params.guest_len, &n, 1);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_SECRET encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(pages, n);

	/*
	 * The secret must be copied into contiguous memory region, lets verify
	 * that userspace memory pages are contiguous before we issue command.
	 */
	if (get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	memset(&data, 0, sizeof(data));

	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	data.guest_address = __sme_page_pa(pages[0]) + offset;
	data.guest_len = params.guest_len;

	blob = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(blob)) {
		ret = PTR_ERR(blob);
		goto e_unpin_memory;
	}

	data.trans_address = __psp_pa(blob);
	data.trans_len = params.trans_len;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto e_free_blob;
	}
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;

	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_SECRET, &data, &argp->error);

	kfree(hdr);

e_free_blob:
	kfree(blob);
e_unpin_memory:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < n; i++) {
		set_page_dirty_lock(pages[i]);
		mark_page_accessed(pages[i]);
	}
	sev_unpin_memory(kvm, pages, n);
	return ret;
}

static int sev_get_attestation_report(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *report = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_attestation_report data;
	struct kvm_sev_attestation_report params;
	void __user *p;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE)
			return -EINVAL;

		blob = kzalloc(params.len, GFP_KERNEL_ACCOUNT);
		if (!blob)
			return -ENOMEM;

		data.address = __psp_pa(blob);
		data.len = params.len;
		memcpy(data.mnonce, params.mnonce, sizeof(params.mnonce));
	}
cmd:
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_ATTESTATION_REPORT, &data, &argp->error);
	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data.len;
	if (copy_to_user(report, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
	return ret;
}

/* Userspace wants to query session length. */
static int
__sev_send_start_query_session_length(struct kvm *kvm, struct kvm_sev_cmd *argp,
				      struct kvm_sev_send_start *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, &data, &argp->error);

	params->session_len = data.session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

	return ret;
}

static int sev_send_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start data;
	struct kvm_sev_send_start params;
	void *amd_certs, *session_data;
	void *pdh_cert, *plat_certs;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
				sizeof(struct kvm_sev_send_start)))
		return -EFAULT;

	/* if session_len is zero, userspace wants to query the session length */
	if (!params.session_len)
		return __sev_send_start_query_session_length(kvm, argp,
				&params);

	/* some sanity checks */
	if (!params.pdh_cert_uaddr || !params.pdh_cert_len ||
	    !params.session_uaddr || params.session_len > SEV_FW_BLOB_MAX_SIZE)
		return -EINVAL;

	/* allocate the memory to hold the session data blob */
	session_data = kzalloc(params.session_len, GFP_KERNEL_ACCOUNT);
	if (!session_data)
		return -ENOMEM;

	/* copy the certificate blobs from userspace */
	pdh_cert = psp_copy_user_blob(params.pdh_cert_uaddr,
				params.pdh_cert_len);
	if (IS_ERR(pdh_cert)) {
		ret = PTR_ERR(pdh_cert);
		goto e_free_session;
	}

	plat_certs = psp_copy_user_blob(params.plat_certs_uaddr,
				params.plat_certs_len);
	if (IS_ERR(plat_certs)) {
		ret = PTR_ERR(plat_certs);
		goto e_free_pdh;
	}

	amd_certs = psp_copy_user_blob(params.amd_certs_uaddr,
				params.amd_certs_len);
	if (IS_ERR(amd_certs)) {
		ret = PTR_ERR(amd_certs);
		goto e_free_plat_cert;
	}

	/* populate the FW SEND_START field with system physical address */
	memset(&data, 0, sizeof(data));
	data.pdh_cert_address = __psp_pa(pdh_cert);
	data.pdh_cert_len = params.pdh_cert_len;
	data.plat_certs_address = __psp_pa(plat_certs);
	data.plat_certs_len = params.plat_certs_len;
	data.amd_certs_address = __psp_pa(amd_certs);
	data.amd_certs_len = params.amd_certs_len;
	data.session_address = __psp_pa(session_data);
	data.session_len = params.session_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, &data, &argp->error);

	if (!ret && copy_to_user((void __user *)(uintptr_t)params.session_uaddr,
			session_data, params.session_len)) {
		ret = -EFAULT;
		goto e_free_amd_cert;
	}

	params.policy = data.policy;
	params.session_len = data.session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

e_free_amd_cert:
	kfree(amd_certs);
e_free_plat_cert:
	kfree(plat_certs);
e_free_pdh:
	kfree(pdh_cert);
e_free_session:
	kfree(session_data);
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
__sev_send_update_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_sev_send_update_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
			 sizeof(struct kvm_sev_send_update_data)))
		ret = -EFAULT;

	return ret;
}

static int sev_send_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data data;
	struct kvm_sev_send_update_data params;
	void *hdr, *trans_data;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_send_update_data)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return __sev_send_update_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_uaddr ||
	    !params.guest_len || !params.hdr_uaddr)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if ((params.guest_len + offset > PAGE_SIZE))
		return -EINVAL;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 0);
	if (IS_ERR(guest_page))
		return PTR_ERR(guest_page);

	/* allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr)
		goto e_unpin;

	trans_data = kzalloc(params.trans_len, GFP_KERNEL_ACCOUNT);
	if (!trans_data)
		goto e_free_hdr;

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_address = __psp_pa(trans_data);
	data.trans_len = params.trans_len;

	/* The SEND_UPDATE_DATA command requires C-bit to be always set. */
	data.guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) + offset;
	data.guest_address |= sev_me_mask;
	data.guest_len = params.guest_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, &data, &argp->error);

	if (ret)
		goto e_free_trans_data;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	/* Copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len))
		ret = -EFAULT;

e_free_trans_data:
	kfree(trans_data);
e_free_hdr:
	kfree(hdr);
e_unpin:
	sev_unpin_memory(kvm, guest_page, n);

	return ret;
}

static int sev_send_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_SEND_FINISH, &data, &argp->error);
}

static int sev_send_cancel(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_cancel data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_SEND_CANCEL, &data, &argp->error);
}

static int sev_receive_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_start start;
	struct kvm_sev_receive_start params;
	int *error = &argp->error;
	void *session_data;
	void *pdh_data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	/* Get parameter from the userspace */
	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_start)))
		return -EFAULT;

	/* some sanity checks */
	if (!params.pdh_uaddr || !params.pdh_len ||
	    !params.session_uaddr || !params.session_len)
		return -EINVAL;

	pdh_data = psp_copy_user_blob(params.pdh_uaddr, params.pdh_len);
	if (IS_ERR(pdh_data))
		return PTR_ERR(pdh_data);

	session_data = psp_copy_user_blob(params.session_uaddr,
			params.session_len);
	if (IS_ERR(session_data)) {
		ret = PTR_ERR(session_data);
		goto e_free_pdh;
	}

	memset(&start, 0, sizeof(start));
	start.handle = params.handle;
	start.policy = params.policy;
	start.pdh_cert_address = __psp_pa(pdh_data);
	start.pdh_cert_len = params.pdh_len;
	start.session_address = __psp_pa(session_data);
	start.session_len = params.session_len;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_RECEIVE_START, &start,
				error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start.handle, error);
	if (ret) {
		sev_decommission(start.handle);
		goto e_free_session;
	}

	params.handle = start.handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data,
			 &params, sizeof(struct kvm_sev_receive_start))) {
		ret = -EFAULT;
		sev_unbind_asid(kvm, start.handle);
		goto e_free_session;
	}

    	sev->handle = start.handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_data);
e_free_pdh:
	kfree(pdh_data);

	return ret;
}

static int sev_receive_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_data params;
	struct sev_data_receive_update_data data;
	void *hdr = NULL, *trans = NULL;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_update_data)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_uaddr || !params.guest_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if ((params.guest_len + offset > PAGE_SIZE))
		return -EINVAL;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	trans = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto e_free_hdr;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_address = __psp_pa(trans);
	data.trans_len = params.trans_len;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 1);
	if (IS_ERR(guest_page)) {
		ret = PTR_ERR(guest_page);
		goto e_free_trans;
	}

	/*
	 * Flush (on non-coherent CPUs) before RECEIVE_UPDATE_DATA, the PSP
	 * encrypts the written data with the guest's key, and the cache may
	 * contain dirty, unencrypted data.
	 */
	sev_clflush_pages(guest_page, n);

	/* The RECEIVE_UPDATE_DATA command requires C-bit to be always set. */
	data.guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) + offset;
	data.guest_address |= sev_me_mask;
	data.guest_len = params.guest_len;
	data.handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_RECEIVE_UPDATE_DATA, &data,
				&argp->error);

	sev_unpin_memory(kvm, guest_page, n);

e_free_trans:
	kfree(trans);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int sev_receive_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_finish data;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data.handle = sev->handle;
	return sev_issue_cmd(kvm, SEV_CMD_RECEIVE_FINISH, &data, &argp->error);
}

static bool is_cmd_allowed_from_mirror(u32 cmd_id)
{
	/*
	 * Allow mirrors VM to call KVM_SEV_LAUNCH_UPDATE_VMSA to enable SEV-ES
	 * active mirror VMs. Also allow the debugging and status commands.
	 */
	if (cmd_id == KVM_SEV_LAUNCH_UPDATE_VMSA ||
	    cmd_id == KVM_SEV_GUEST_STATUS || cmd_id == KVM_SEV_DBG_DECRYPT ||
	    cmd_id == KVM_SEV_DBG_ENCRYPT)
		return true;

	return false;
}

static int sev_lock_two_vms(struct kvm *dst_kvm, struct kvm *src_kvm)
{
	struct kvm_sev_info *dst_sev = &to_kvm_svm(dst_kvm)->sev_info;
	struct kvm_sev_info *src_sev = &to_kvm_svm(src_kvm)->sev_info;
	int r = -EBUSY;

	if (dst_kvm == src_kvm)
		return -EINVAL;

	/*
	 * Bail if these VMs are already involved in a migration to avoid
	 * deadlock between two VMs trying to migrate to/from each other.
	 */
	if (atomic_cmpxchg_acquire(&dst_sev->migration_in_progress, 0, 1))
		return -EBUSY;

	if (atomic_cmpxchg_acquire(&src_sev->migration_in_progress, 0, 1))
		goto release_dst;

	r = -EINTR;
	if (mutex_lock_killable(&dst_kvm->lock))
		goto release_src;
	if (mutex_lock_killable_nested(&src_kvm->lock, SINGLE_DEPTH_NESTING))
		goto unlock_dst;
	return 0;

unlock_dst:
	mutex_unlock(&dst_kvm->lock);
release_src:
	atomic_set_release(&src_sev->migration_in_progress, 0);
release_dst:
	atomic_set_release(&dst_sev->migration_in_progress, 0);
	return r;
}

static void sev_unlock_two_vms(struct kvm *dst_kvm, struct kvm *src_kvm)
{
	struct kvm_sev_info *dst_sev = &to_kvm_svm(dst_kvm)->sev_info;
	struct kvm_sev_info *src_sev = &to_kvm_svm(src_kvm)->sev_info;

	mutex_unlock(&dst_kvm->lock);
	mutex_unlock(&src_kvm->lock);
	atomic_set_release(&dst_sev->migration_in_progress, 0);
	atomic_set_release(&src_sev->migration_in_progress, 0);
}

/* vCPU mutex subclasses.  */
enum sev_migration_role {
	SEV_MIGRATION_SOURCE = 0,
	SEV_MIGRATION_TARGET,
	SEV_NR_MIGRATION_ROLES,
};

static int sev_lock_vcpus_for_migration(struct kvm *kvm,
					enum sev_migration_role role)
{
	struct kvm_vcpu *vcpu;
	unsigned long i, j;
	bool first = true;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (mutex_lock_killable_nested(&vcpu->mutex, role))
			goto out_unlock;

		if (first) {
			/*
			 * Reset the role to one that avoids colliding with
			 * the role used for the first vcpu mutex.
			 */
			role = SEV_NR_MIGRATION_ROLES;
			first = false;
		} else {
			mutex_release(&vcpu->mutex.dep_map, _THIS_IP_);
		}
	}

	return 0;

out_unlock:

	first = true;
	kvm_for_each_vcpu(j, vcpu, kvm) {
		if (i == j)
			break;

		if (first)
			first = false;
		else
			mutex_acquire(&vcpu->mutex.dep_map, role, 0, _THIS_IP_);


		mutex_unlock(&vcpu->mutex);
	}
	return -EINTR;
}

static void sev_unlock_vcpus_for_migration(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;
	bool first = true;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (first)
			first = false;
		else
			mutex_acquire(&vcpu->mutex.dep_map,
				      SEV_NR_MIGRATION_ROLES, 0, _THIS_IP_);

		mutex_unlock(&vcpu->mutex);
	}
}

static void sev_migrate_from(struct kvm *dst_kvm, struct kvm *src_kvm)
{
	struct kvm_sev_info *dst = &to_kvm_svm(dst_kvm)->sev_info;
	struct kvm_sev_info *src = &to_kvm_svm(src_kvm)->sev_info;
	struct kvm_vcpu *dst_vcpu, *src_vcpu;
	struct vcpu_svm *dst_svm, *src_svm;
	struct kvm_sev_info *mirror;
	unsigned long i;

	dst->active = true;
	dst->asid = src->asid;
	dst->handle = src->handle;
	dst->pages_locked = src->pages_locked;
	dst->enc_context_owner = src->enc_context_owner;
	dst->es_active = src->es_active;

	src->asid = 0;
	src->active = false;
	src->handle = 0;
	src->pages_locked = 0;
	src->enc_context_owner = NULL;
	src->es_active = false;

	list_cut_before(&dst->regions_list, &src->regions_list, &src->regions_list);

	/*
	 * If this VM has mirrors, "transfer" each mirror's refcount of the
	 * source to the destination (this KVM).  The caller holds a reference
	 * to the source, so there's no danger of use-after-free.
	 */
	list_cut_before(&dst->mirror_vms, &src->mirror_vms, &src->mirror_vms);
	list_for_each_entry(mirror, &dst->mirror_vms, mirror_entry) {
		kvm_get_kvm(dst_kvm);
		kvm_put_kvm(src_kvm);
		mirror->enc_context_owner = dst_kvm;
	}

	/*
	 * If this VM is a mirror, remove the old mirror from the owners list
	 * and add the new mirror to the list.
	 */
	if (is_mirroring_enc_context(dst_kvm)) {
		struct kvm_sev_info *owner_sev_info =
			&to_kvm_svm(dst->enc_context_owner)->sev_info;

		list_del(&src->mirror_entry);
		list_add_tail(&dst->mirror_entry, &owner_sev_info->mirror_vms);
	}

	kvm_for_each_vcpu(i, dst_vcpu, dst_kvm) {
		dst_svm = to_svm(dst_vcpu);

		sev_init_vmcb(dst_svm);

		if (!dst->es_active)
			continue;

		/*
		 * Note, the source is not required to have the same number of
		 * vCPUs as the destination when migrating a vanilla SEV VM.
		 */
		src_vcpu = kvm_get_vcpu(dst_kvm, i);
		src_svm = to_svm(src_vcpu);

		/*
		 * Transfer VMSA and GHCB state to the destination.  Nullify and
		 * clear source fields as appropriate, the state now belongs to
		 * the destination.
		 */
		memcpy(&dst_svm->sev_es, &src_svm->sev_es, sizeof(src_svm->sev_es));
		dst_svm->vmcb->control.ghcb_gpa = src_svm->vmcb->control.ghcb_gpa;
		dst_svm->vmcb->control.vmsa_pa = src_svm->vmcb->control.vmsa_pa;
		dst_vcpu->arch.guest_state_protected = true;

		memset(&src_svm->sev_es, 0, sizeof(src_svm->sev_es));
		src_svm->vmcb->control.ghcb_gpa = INVALID_PAGE;
		src_svm->vmcb->control.vmsa_pa = INVALID_PAGE;
		src_vcpu->arch.guest_state_protected = false;
	}
}

static int sev_check_source_vcpus(struct kvm *dst, struct kvm *src)
{
	struct kvm_vcpu *src_vcpu;
	unsigned long i;

	if (!sev_es_guest(src))
		return 0;

	if (atomic_read(&src->online_vcpus) != atomic_read(&dst->online_vcpus))
		return -EINVAL;

	kvm_for_each_vcpu(i, src_vcpu, src) {
		if (!src_vcpu->arch.guest_state_protected)
			return -EINVAL;
	}

	return 0;
}

int sev_vm_move_enc_context_from(struct kvm *kvm, unsigned int source_fd)
{
	struct kvm_sev_info *dst_sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_info *src_sev, *cg_cleanup_sev;
	struct file *source_kvm_file;
	struct kvm *source_kvm;
	bool charged = false;
	int ret;

	source_kvm_file = fget(source_fd);
	if (!file_is_kvm(source_kvm_file)) {
		ret = -EBADF;
		goto out_fput;
	}

	source_kvm = source_kvm_file->private_data;
	ret = sev_lock_two_vms(kvm, source_kvm);
	if (ret)
		goto out_fput;

	if (sev_guest(kvm) || !sev_guest(source_kvm)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	src_sev = &to_kvm_svm(source_kvm)->sev_info;

	dst_sev->misc_cg = get_current_misc_cg();
	cg_cleanup_sev = dst_sev;
	if (dst_sev->misc_cg != src_sev->misc_cg) {
		ret = sev_misc_cg_try_charge(dst_sev);
		if (ret)
			goto out_dst_cgroup;
		charged = true;
	}

	ret = sev_lock_vcpus_for_migration(kvm, SEV_MIGRATION_SOURCE);
	if (ret)
		goto out_dst_cgroup;
	ret = sev_lock_vcpus_for_migration(source_kvm, SEV_MIGRATION_TARGET);
	if (ret)
		goto out_dst_vcpu;

	ret = sev_check_source_vcpus(kvm, source_kvm);
	if (ret)
		goto out_source_vcpu;

	sev_migrate_from(kvm, source_kvm);
	kvm_vm_dead(source_kvm);
	cg_cleanup_sev = src_sev;
	ret = 0;

out_source_vcpu:
	sev_unlock_vcpus_for_migration(source_kvm);
out_dst_vcpu:
	sev_unlock_vcpus_for_migration(kvm);
out_dst_cgroup:
	/* Operates on the source on success, on the destination on failure.  */
	if (charged)
		sev_misc_cg_uncharge(cg_cleanup_sev);
	put_misc_cg(cg_cleanup_sev->misc_cg);
	cg_cleanup_sev->misc_cg = NULL;
out_unlock:
	sev_unlock_two_vms(kvm, source_kvm);
out_fput:
	if (source_kvm_file)
		fput(source_kvm_file);
	return ret;
}

static void *snp_context_create(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void *context = NULL, *certs_data = NULL, *resp_page = NULL;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_gctx_create data = {};
	int rc;

	/* Allocate memory used for the certs data in SNP guest request */
	certs_data = kmalloc(SEV_FW_BLOB_MAX_SIZE, GFP_KERNEL_ACCOUNT);
	if (!certs_data)
		return NULL;

	/* Allocate memory for context page */
	context = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!context)
		goto e_free;

	/* Allocate a firmware buffer used during the guest command handling. */
	resp_page = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!resp_page)
		goto e_free;

	data.gctx_paddr = __psp_pa(context);
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_GCTX_CREATE, &data, &argp->error);
	if (rc)
		goto e_free;

	sev->snp_certs_data = certs_data;

	return context;

e_free:
	snp_free_firmware_page(context);
	kfree(certs_data);
	return NULL;
}

static int snp_bind_asid(struct kvm *kvm, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_activate data = {0};

	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.asid   = sev_get_asid(kvm);
	return sev_issue_cmd(kvm, SEV_CMD_SNP_ACTIVATE, &data, error);
}

static int snp_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_start start = {0};
	struct kvm_sev_snp_launch_start params;
	int rc;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	sev->snp_context = snp_context_create(kvm, argp);
	if (!sev->snp_context)
		return -ENOTTY;

	start.gctx_paddr = __psp_pa(sev->snp_context);
	start.policy = params.policy;
	memcpy(start.gosvw, params.gosvw, sizeof(params.gosvw));
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_START, &start, &argp->error);
	if (rc)
		goto e_free_context;

	sev->fd = argp->sev_fd;
	rc = snp_bind_asid(kvm, &argp->error);
	if (rc)
		goto e_free_context;

	return 0;

e_free_context:
	snp_decommission_context(kvm);

	return rc;
}

static bool is_hva_registered(struct kvm *kvm, hva_t hva, size_t len)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct enc_region *i;

	lockdep_assert_held(&kvm->lock);

	list_for_each_entry(i, head, list) {
		u64 start = i->uaddr;
		u64 end = start + i->size;

		if (start <= hva && end >= (hva + len))
			return true;
	}

	return false;
}

static int snp_mark_unmergable(struct kvm *kvm, u64 start, u64 size)
{
	struct vm_area_struct *vma;
	u64 end = start + size;
	int ret;

	do {
		vma = find_vma_intersection(kvm->mm, start, end);
		if (!vma) {
			ret = -EINVAL;
			break;
		}

		ret = ksm_madvise(vma, vma->vm_start, vma->vm_end,
				  MADV_UNMERGEABLE, &vma->vm_flags);
		if (ret)
			break;

		start = vma->vm_end;
	} while (end > vma->vm_end);

	return ret;
}

static int snp_launch_update(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update data = {0};
	struct kvm_sev_snp_launch_update params;
	unsigned long npages, pfn, n = 0;
	int *error = &argp->error;
	struct page **inpages;
	int ret, i, level;
	u64 gfn;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	/* Verify that the specified address range is registered. */
	if (!is_hva_registered(kvm, params.uaddr, params.len))
		return -EINVAL;

	mmap_write_lock(kvm->mm);
	ret = snp_mark_unmergable(kvm, params.uaddr, params.len);
	mmap_write_unlock(kvm->mm);
	if (ret)
		return -EFAULT;

	/*
	 * The userspace memory is already locked so technically we don't
	 * need to lock it again. Later part of the function needs to know
	 * pfn so call the sev_pin_memory() so that we can get the list of
	 * pages to iterate through.
	 */
	inpages = sev_pin_memory(kvm, params.uaddr, params.len, &npages, 1);
	if (!inpages)
		return -ENOMEM;

	/*
	 * Verify that all the pages are marked shared in the RMP table before
	 * going further. This is avoid the cases where the userspace may try
	 * updating the same page twice.
	 */
	for (i = 0; i < npages; i++) {
		if (snp_lookup_rmpentry(page_to_pfn(inpages[i]), &level) != 0) {
			sev_unpin_memory(kvm, inpages, npages);
			return -EFAULT;
		}
	}

	gfn = params.start_gfn;
	level = PG_LEVEL_4K;
	data.gctx_paddr = __psp_pa(sev->snp_context);

	for (i = 0; i < npages; i++) {
		pfn = page_to_pfn(inpages[i]);

		ret = rmp_make_private(pfn, gfn << PAGE_SHIFT, level, sev_get_asid(kvm), true);
		if (ret) {
			ret = -EFAULT;
			goto e_unpin;
		}

		n++;
		data.address = __sme_page_pa(inpages[i]);
		data.page_size = X86_TO_RMP_PG_LEVEL(level);
		data.page_type = params.page_type;
		data.vmpl3_perms = params.vmpl3_perms;
		data.vmpl2_perms = params.vmpl2_perms;
		data.vmpl1_perms = params.vmpl1_perms;
		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE, &data, error);
		if (ret) {
			/*
			 * If the command failed then need to reclaim the page.
			 */
			snp_page_reclaim(pfn);
			goto e_unpin;
		}

		gfn++;
	}

e_unpin:
	/* Content of memory is updated, mark pages dirty */
	for (i = 0; i < n; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);

		/*
		 * If its an error, then update RMP entry to change page ownership
		 * to the hypervisor.
		 */
		if (ret)
			host_rmp_make_shared(pfn, level, true);
	}

	/* Unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);

	return ret;
}

#define INITIAL_VMSA_GPA 0xFFFFFFFFF000

static int snp_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update data = {};
	int i, ret;

	data.gctx_paddr = __psp_pa(sev->snp_context);
	data.page_type = SNP_PAGE_TYPE_VMSA;

	for (i = 0; i < kvm->created_vcpus; i++) {
		struct vcpu_svm *svm = to_svm(xa_load(&kvm->vcpu_array, i));
		u64 pfn = __pa(svm->sev_es.vmsa) >> PAGE_SHIFT;

		/* Perform some pre-encryption checks against the VMSA */
		ret = sev_es_sync_vmsa(svm);
		if (ret)
			return ret;

		/* Transition the VMSA page to a firmware state. */
		ret = rmp_make_private(pfn, INITIAL_VMSA_GPA, PG_LEVEL_4K, sev->asid, true);
		if (ret)
			return ret;

		/* Issue the SNP command to encrypt the VMSA */
		data.address = __sme_pa(svm->sev_es.vmsa);
		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE,
				      &data, &argp->error);
		if (ret) {
			snp_page_reclaim(pfn);
			return ret;
		}

		svm->vcpu.arch.guest_state_protected = true;
	}

	return 0;
}

static int snp_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_finish *data;
	void *id_block = NULL, *id_auth = NULL;
	struct kvm_sev_snp_launch_finish params;
	int ret;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	/* Measure all vCPUs using LAUNCH_UPDATE before we finalize the launch flow. */
	ret = snp_launch_update_vmsa(kvm, argp);
	if (ret)
		return ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	if (params.id_block_en) {
		id_block = psp_copy_user_blob(params.id_block_uaddr, KVM_SEV_SNP_ID_BLOCK_SIZE);
		if (IS_ERR(id_block)) {
			ret = PTR_ERR(id_block);
			goto e_free;
		}

		data->id_block_en = 1;
		data->id_block_paddr = __sme_pa(id_block);
	}

	if (params.auth_key_en) {
		id_auth = psp_copy_user_blob(params.id_auth_uaddr, KVM_SEV_SNP_ID_AUTH_SIZE);
		if (IS_ERR(id_auth)) {
			ret = PTR_ERR(id_auth);
			goto e_free_id_block;
		}

		data->auth_key_en = 1;
		data->id_auth_paddr = __sme_pa(id_auth);
	}

	data->gctx_paddr = __psp_pa(sev->snp_context);
	ret = sev_issue_cmd(kvm, SEV_CMD_SNP_LAUNCH_FINISH, data, &argp->error);

	kfree(id_auth);

e_free_id_block:
	kfree(id_block);

e_free:
	kfree(data);

	return ret;
}

int sev_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r;

	if (!sev_enabled)
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	/* Only the enc_context_owner handles some memory enc operations. */
	if (is_mirroring_enc_context(kvm) &&
	    !is_cmd_allowed_from_mirror(sev_cmd.id)) {
		r = -EINVAL;
		goto out;
	}

	switch (sev_cmd.id) {
	case KVM_SEV_SNP_INIT:
		if (!sev_snp_enabled) {
			r = -ENOTTY;
			goto out;
		}
		fallthrough;
	case KVM_SEV_ES_INIT:
		if (!sev_es_enabled) {
			r = -ENOTTY;
			goto out;
		}
		fallthrough;
	case KVM_SEV_INIT:
		r = sev_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_START:
		r = sev_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_DATA:
		r = sev_launch_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_VMSA:
		r = sev_launch_update_vmsa(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_MEASURE:
		r = sev_launch_measure(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_FINISH:
		r = sev_launch_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_GUEST_STATUS:
		r = sev_guest_status(kvm, &sev_cmd);
		break;
	case KVM_SEV_DBG_DECRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, true);
		break;
	case KVM_SEV_DBG_ENCRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, false);
		break;
	case KVM_SEV_LAUNCH_SECRET:
		r = sev_launch_secret(kvm, &sev_cmd);
		break;
	case KVM_SEV_GET_ATTESTATION_REPORT:
		r = sev_get_attestation_report(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_START:
		r = sev_send_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_UPDATE_DATA:
		r = sev_send_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_FINISH:
		r = sev_send_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_CANCEL:
		r = sev_send_cancel(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_START:
		r = sev_receive_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_UPDATE_DATA:
		r = sev_receive_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_FINISH:
		r = sev_receive_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_START:
		r = snp_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_UPDATE:
		r = snp_launch_update(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_FINISH:
		r = snp_launch_finish(kvm, &sev_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

static bool is_range_hugetlb(struct kvm *kvm, struct kvm_enc_region *range)
{
	struct vm_area_struct *vma;
	u64 start, end;
	bool ret = true;

	start = range->addr;
	end = start + range->size;

	mmap_read_lock(kvm->mm);

	do {
		vma = find_vma_intersection(kvm->mm, start, end);
		if (!vma)
			goto unlock;

		if (is_vm_hugetlb_page(vma))
			goto unlock;

		start = vma->vm_end;
	} while (end > vma->vm_end);

	ret = false;

unlock:
	mmap_read_unlock(kvm->mm);
	return ret;
}

int sev_mem_enc_register_region(struct kvm *kvm,
				struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct enc_region *region;
	int ret = 0;

	if (!sev_guest(kvm))
		return -ENOTTY;

	/* If kvm is mirroring encryption context it isn't responsible for it */
	if (is_mirroring_enc_context(kvm))
		return -EINVAL;

	if (range->addr > ULONG_MAX || range->size > ULONG_MAX)
		return -EINVAL;

	/*
	 * SEV-SNP does not support the backing pages from the HugeTLB. Verify
	 * that the registered memory range is not from the HugeTLB.
	 */
	if (sev_snp_guest(kvm) && is_range_hugetlb(kvm, range))
		return -EINVAL;

	region = kzalloc(sizeof(*region), GFP_KERNEL_ACCOUNT);
	if (!region)
		return -ENOMEM;

	mutex_lock(&kvm->lock);
	region->pages = sev_pin_memory(kvm, range->addr, range->size, &region->npages, 1);
	if (IS_ERR(region->pages)) {
		ret = PTR_ERR(region->pages);
		mutex_unlock(&kvm->lock);
		goto e_free;
	}

	region->uaddr = range->addr;
	region->size = range->size;

	list_add_tail(&region->list, &sev->regions_list);
	mutex_unlock(&kvm->lock);

	/*
	 * The guest may change the memory encryption attribute from C=0 -> C=1
	 * or vice versa for this memory range. Lets make sure caches are
	 * flushed to ensure that guest data gets written into memory with
	 * correct C-bit.
	 */
	sev_clflush_pages(region->pages, region->npages);

	return ret;

e_free:
	kfree(region);
	return ret;
}

static struct enc_region *
find_enc_region(struct kvm *kvm, struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct enc_region *i;

	list_for_each_entry(i, head, list) {
		if (i->uaddr == range->addr &&
		    i->size == range->size)
			return i;
	}

	return NULL;
}

static void __unregister_enc_region_locked(struct kvm *kvm,
					   struct enc_region *region)
{
	unsigned long i, pfn;
	int level;

	/*
	 * The guest memory pages are assigned in the RMP table. Unassign it
	 * before releasing the memory.
	 */
	if (sev_snp_guest(kvm)) {
		for (i = 0; i < region->npages; i++) {
			pfn = page_to_pfn(region->pages[i]);

			if (!snp_lookup_rmpentry(pfn, &level))
				continue;

			cond_resched();

			if (level > PG_LEVEL_4K)
				pfn &= ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);

			host_rmp_make_shared(pfn, level, true);
		}
	}

	sev_unpin_memory(kvm, region->pages, region->npages);
	list_del(&region->list);
	kfree(region);
}

int sev_mem_enc_unregister_region(struct kvm *kvm,
				  struct kvm_enc_region *range)
{
	struct enc_region *region;
	int ret;

	/* If kvm is mirroring encryption context it isn't responsible for it */
	if (is_mirroring_enc_context(kvm))
		return -EINVAL;

	mutex_lock(&kvm->lock);

	if (!sev_guest(kvm)) {
		ret = -ENOTTY;
		goto failed;
	}

	region = find_enc_region(kvm, range);
	if (!region) {
		ret = -EINVAL;
		goto failed;
	}

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	__unregister_enc_region_locked(kvm, region);

	mutex_unlock(&kvm->lock);
	return 0;

failed:
	mutex_unlock(&kvm->lock);
	return ret;
}

int sev_vm_copy_enc_context_from(struct kvm *kvm, unsigned int source_fd)
{
	struct file *source_kvm_file;
	struct kvm *source_kvm;
	struct kvm_sev_info *source_sev, *mirror_sev;
	int ret;

	source_kvm_file = fget(source_fd);
	if (!file_is_kvm(source_kvm_file)) {
		ret = -EBADF;
		goto e_source_fput;
	}

	source_kvm = source_kvm_file->private_data;
	ret = sev_lock_two_vms(kvm, source_kvm);
	if (ret)
		goto e_source_fput;

	/*
	 * Mirrors of mirrors should work, but let's not get silly.  Also
	 * disallow out-of-band SEV/SEV-ES init if the target is already an
	 * SEV guest, or if vCPUs have been created.  KVM relies on vCPUs being
	 * created after SEV/SEV-ES initialization, e.g. to init intercepts.
	 */
	if (sev_guest(kvm) || !sev_guest(source_kvm) ||
	    is_mirroring_enc_context(source_kvm) || kvm->created_vcpus) {
		ret = -EINVAL;
		goto e_unlock;
	}

	/*
	 * The mirror kvm holds an enc_context_owner ref so its asid can't
	 * disappear until we're done with it
	 */
	source_sev = &to_kvm_svm(source_kvm)->sev_info;
	kvm_get_kvm(source_kvm);
	mirror_sev = &to_kvm_svm(kvm)->sev_info;
	list_add_tail(&mirror_sev->mirror_entry, &source_sev->mirror_vms);

	/* Set enc_context_owner and copy its encryption context over */
	mirror_sev->enc_context_owner = source_kvm;
	mirror_sev->active = true;
	mirror_sev->asid = source_sev->asid;
	mirror_sev->fd = source_sev->fd;
	mirror_sev->es_active = source_sev->es_active;
	mirror_sev->handle = source_sev->handle;
	INIT_LIST_HEAD(&mirror_sev->regions_list);
	INIT_LIST_HEAD(&mirror_sev->mirror_vms);
	ret = 0;

	/*
	 * Do not copy ap_jump_table. Since the mirror does not share the same
	 * KVM contexts as the original, and they may have different
	 * memory-views.
	 */

e_unlock:
	sev_unlock_two_vms(kvm, source_kvm);
e_source_fput:
	if (source_kvm_file)
		fput(source_kvm_file);
	return ret;
}

static int snp_decommission_context(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_decommission data = {};
	int ret;

	/* If context is not created then do nothing */
	if (!sev->snp_context)
		return 0;

	data.gctx_paddr = __sme_pa(sev->snp_context);
	ret = snp_guest_decommission(&data, NULL);
	if (WARN_ONCE(ret, "failed to release guest context"))
		return ret;

	/* free the context page now */
	snp_free_firmware_page(sev->snp_context);
	sev->snp_context = NULL;

	kfree(sev->snp_certs_data);

	return 0;
}

void sev_vm_destroy(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct list_head *pos, *q;

	if (!sev_guest(kvm))
		return;

	WARN_ON(!list_empty(&sev->mirror_vms));

	/* If this is a mirror_kvm release the enc_context_owner and skip sev cleanup */
	if (is_mirroring_enc_context(kvm)) {
		struct kvm *owner_kvm = sev->enc_context_owner;

		mutex_lock(&owner_kvm->lock);
		list_del(&sev->mirror_entry);
		mutex_unlock(&owner_kvm->lock);
		kvm_put_kvm(owner_kvm);
		return;
	}

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	/*
	 * if userspace was terminated before unregistering the memory regions
	 * then lets unpin all the registered memory.
	 */
	if (!list_empty(head)) {
		list_for_each_safe(pos, q, head) {
			__unregister_enc_region_locked(kvm,
				list_entry(pos, struct enc_region, list));
			cond_resched();
		}
	}

	if (sev_snp_guest(kvm)) {
		if (snp_decommission_context(kvm)) {
			WARN_ONCE(1, "Failed to free SNP guest context, leaking asid!\n");
			return;
		}
	} else {
		sev_unbind_asid(kvm, sev->handle);
	}

	sev_asid_free(sev);
}

void __init sev_set_cpu_caps(void)
{
	if (!sev_enabled)
		kvm_cpu_cap_clear(X86_FEATURE_SEV);
	if (!sev_es_enabled)
		kvm_cpu_cap_clear(X86_FEATURE_SEV_ES);
}

void __init sev_hardware_setup(void)
{
#ifdef CONFIG_KVM_AMD_SEV
	unsigned int eax, ebx, ecx, edx, sev_asid_count, sev_es_asid_count;
	bool sev_snp_supported = false;
	bool sev_es_supported = false;
	bool sev_supported = false;

	if (!sev_enabled || !npt_enabled)
		goto out;

	/*
	 * SEV must obviously be supported in hardware.  Sanity check that the
	 * CPU supports decode assists, which is mandatory for SEV guests to
	 * support instruction emulation.
	 */
	if (!boot_cpu_has(X86_FEATURE_SEV) ||
	    WARN_ON_ONCE(!boot_cpu_has(X86_FEATURE_DECODEASSISTS)))
		goto out;

	/* Retrieve SEV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);

	/* Set encryption bit location for SEV-ES guests */
	sev_enc_bit = ebx & 0x3f;

	/* Maximum number of encrypted guests supported simultaneously */
	max_sev_asid = ecx;
	if (!max_sev_asid)
		goto out;

	/* Minimum ASID value that should be used for SEV guest */
	min_sev_asid = edx;
	sev_me_mask = 1UL << (ebx & 0x3f);

	/*
	 * Initialize SEV ASID bitmaps. Allocate space for ASID 0 in the bitmap,
	 * even though it's never used, so that the bitmap is indexed by the
	 * actual ASID.
	 */
	nr_asids = max_sev_asid + 1;
	sev_asid_bitmap = bitmap_zalloc(nr_asids, GFP_KERNEL);
	if (!sev_asid_bitmap)
		goto out;

	sev_reclaim_asid_bitmap = bitmap_zalloc(nr_asids, GFP_KERNEL);
	if (!sev_reclaim_asid_bitmap) {
		bitmap_free(sev_asid_bitmap);
		sev_asid_bitmap = NULL;
		goto out;
	}

	sev_asid_count = max_sev_asid - min_sev_asid + 1;
	if (misc_cg_set_capacity(MISC_CG_RES_SEV, sev_asid_count))
		goto out;

	pr_info("SEV supported: %u ASIDs\n", sev_asid_count);
	sev_supported = true;

	/* SEV-ES support requested? */
	if (!sev_es_enabled)
		goto out;

	/*
	 * SEV-ES requires MMIO caching as KVM doesn't have access to the guest
	 * instruction stream, i.e. can't emulate in response to a #NPF and
	 * instead relies on #NPF(RSVD) being reflected into the guest as #VC
	 * (the guest can then do a #VMGEXIT to request MMIO emulation).
	 */
	if (!enable_mmio_caching)
		goto out;

	/* Does the CPU support SEV-ES? */
	if (!boot_cpu_has(X86_FEATURE_SEV_ES))
		goto out;

	/* Has the system been allocated ASIDs for SEV-ES? */
	if (min_sev_asid == 1)
		goto out;

	sev_es_asid_count = min_sev_asid - 1;
	if (misc_cg_set_capacity(MISC_CG_RES_SEV_ES, sev_es_asid_count))
		goto out;

	sev_es_supported = true;
	sev_snp_supported = sev_snp_enabled && cpu_feature_enabled(X86_FEATURE_SEV_SNP);

	pr_info("SEV-ES %ssupported: %u ASIDs\n",
		sev_snp_supported ? "and SEV-SNP " : "", sev_es_asid_count);

out:
	sev_enabled = sev_supported;
	sev_es_enabled = sev_es_supported;
	sev_snp_enabled = sev_snp_supported;
#endif
}

void sev_hardware_unsetup(void)
{
	if (!sev_enabled)
		return;

	/* No need to take sev_bitmap_lock, all VMs have been destroyed. */
	sev_flush_asids(1, max_sev_asid);

	bitmap_free(sev_asid_bitmap);
	bitmap_free(sev_reclaim_asid_bitmap);

	misc_cg_set_capacity(MISC_CG_RES_SEV, 0);
	misc_cg_set_capacity(MISC_CG_RES_SEV_ES, 0);
}

int sev_cpu_init(struct svm_cpu_data *sd)
{
	if (!sev_enabled)
		return 0;

	sd->sev_vmcbs = kcalloc(nr_asids, sizeof(void *), GFP_KERNEL);
	if (!sd->sev_vmcbs)
		return -ENOMEM;

	return 0;
}

/*
 * Pages used by hardware to hold guest encrypted state must be flushed before
 * returning them to the system.
 */
static void sev_flush_encrypted_page(struct kvm_vcpu *vcpu, void *va)
{
	int asid = to_kvm_svm(vcpu->kvm)->sev_info.asid;

	/*
	 * Note!  The address must be a kernel address, as regular page walk
	 * checks are performed by VM_PAGE_FLUSH, i.e. operating on a user
	 * address is non-deterministic and unsafe.  This function deliberately
	 * takes a pointer to deter passing in a user address.
	 */
	unsigned long addr = (unsigned long)va;

	/*
	 * If CPU enforced cache coherency for encrypted mappings of the
	 * same physical page is supported, use CLFLUSHOPT instead. NOTE: cache
	 * flush is still needed in order to work properly with DMA devices.
	 */
	if (boot_cpu_has(X86_FEATURE_SME_COHERENT)) {
		clflush_cache_range(va, PAGE_SIZE);
		return;
	}

	/*
	 * VM Page Flush takes a host virtual address and a guest ASID.  Fall
	 * back to WBINVD if this faults so as not to make any problems worse
	 * by leaving stale encrypted data in the cache.
	 */
	if (WARN_ON_ONCE(wrmsrl_safe(MSR_AMD64_VM_PAGE_FLUSH, addr | asid)))
		goto do_wbinvd;

	return;

do_wbinvd:
	wbinvd_on_all_cpus();
}

void sev_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm;

	if (!sev_es_guest(vcpu->kvm))
		return;

	svm = to_svm(vcpu);

	/*
	 * If its an SNP guest, then VMSA was added in the RMP entry as
	 * a guest owned page. Transition the page to hypervisor state
	 * before releasing it back to the system.
	 * Also the page is removed from the kernel direct map, so flush it
	 * later after it is transitioned back to hypervisor state and
	 * restored in the direct map.
	 */
	if (sev_snp_guest(vcpu->kvm)) {
		u64 pfn = __pa(svm->sev_es.vmsa) >> PAGE_SHIFT;

		if (host_rmp_make_shared(pfn, PG_LEVEL_4K, false))
			goto skip_vmsa_free;
	}

	if (vcpu->arch.guest_state_protected)
		sev_flush_encrypted_page(vcpu, svm->sev_es.vmsa);

	__free_page(virt_to_page(svm->sev_es.vmsa));

skip_vmsa_free:
	kvfree(svm->sev_es.ghcb_sa);
}

static inline int svm_map_ghcb(struct vcpu_svm *svm, struct kvm_host_map *map)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 gfn = gpa_to_gfn(control->ghcb_gpa);
	struct kvm_vcpu *vcpu = &svm->vcpu;

	if (kvm_vcpu_map(vcpu, gfn, map)) {
		/* Unable to map GHCB from guest */
		pr_err("error mapping GHCB GFN [%#llx] from guest\n", gfn);
		return -EFAULT;
	}

	if (sev_post_map_gfn(vcpu->kvm, map->gfn, map->pfn)) {
		kvm_vcpu_unmap(vcpu, map, false);
		return -EBUSY;
	}

	return 0;
}

static inline void svm_unmap_ghcb(struct vcpu_svm *svm, struct kvm_host_map *map)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;

	kvm_vcpu_unmap(vcpu, map, true);
	sev_post_unmap_gfn(vcpu->kvm, map->gfn, map->pfn);
}

static void dump_ghcb(struct vcpu_svm *svm)
{
	struct kvm_host_map map;
	unsigned int nbits;
	struct ghcb *ghcb;

	if (svm_map_ghcb(svm, &map))
		return;

	ghcb = map.hva;

	/* Re-use the dump_invalid_vmcb module parameter */
	if (!dump_invalid_vmcb) {
		pr_warn_ratelimited("set kvm_amd.dump_invalid_vmcb=1 to dump internal KVM state.\n");
		goto e_unmap;
	}

	nbits = sizeof(ghcb->save.valid_bitmap) * 8;

	pr_err("GHCB (GPA=%016llx):\n", svm->vmcb->control.ghcb_gpa);
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_code",
	       ghcb->save.sw_exit_code, ghcb_sw_exit_code_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_1",
	       ghcb->save.sw_exit_info_1, ghcb_sw_exit_info_1_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_2",
	       ghcb->save.sw_exit_info_2, ghcb_sw_exit_info_2_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_scratch",
	       ghcb->save.sw_scratch, ghcb_sw_scratch_is_valid(ghcb));
	pr_err("%-20s%*pb\n", "valid_bitmap", nbits, ghcb->save.valid_bitmap);

e_unmap:
	svm_unmap_ghcb(svm, &map);
}

static bool sev_es_sync_to_ghcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm_host_map map;
	struct ghcb *ghcb;

	if (svm_map_ghcb(svm, &map))
		return false;

	ghcb = map.hva;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be returned:
	 *   GPRs RAX, RBX, RCX, RDX
	 *
	 * Copy their values, even if they may not have been written during the
	 * VM-Exit.  It's the guest's responsibility to not consume random data.
	 */
	ghcb_set_rax(ghcb, vcpu->arch.regs[VCPU_REGS_RAX]);
	ghcb_set_rbx(ghcb, vcpu->arch.regs[VCPU_REGS_RBX]);
	ghcb_set_rcx(ghcb, vcpu->arch.regs[VCPU_REGS_RCX]);
	ghcb_set_rdx(ghcb, vcpu->arch.regs[VCPU_REGS_RDX]);

	/*
	 * Copy the return values from the exit_info_{1,2}.
	 */
	ghcb_set_sw_exit_info_1(ghcb, svm->sev_es.ghcb_sw_exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, svm->sev_es.ghcb_sw_exit_info_2);

	/* Sync the scratch buffer area. */
	if (svm->sev_es.ghcb_sa_sync) {
		if (svm->sev_es.ghcb_sa_contained) {
			memcpy(ghcb->shared_buffer + svm->sev_es.ghcb_sa_offset,
			       svm->sev_es.ghcb_sa, svm->sev_es.ghcb_sa_len);
		} else {
			int ret;

			ret = kvm_write_guest(svm->vcpu.kvm,
					      svm->sev_es.ghcb_sa_gpa,
					      svm->sev_es.ghcb_sa, svm->sev_es.ghcb_sa_len);
			if (ret)
				pr_warn_ratelimited("unmap_ghcb: kvm_write_guest failed while syncing scratch area, gpa: %llx, ret: %d\n",
						    svm->sev_es.ghcb_sa_gpa, ret);
		}
		svm->sev_es.ghcb_sa_sync = false;
	}

	trace_kvm_vmgexit_exit(svm->vcpu.vcpu_id, ghcb);

	svm_unmap_ghcb(svm, &map);

	return true;
}

static void sev_es_sync_from_ghcb(struct vcpu_svm *svm, struct ghcb *ghcb)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	u64 exit_code;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be supplied:
	 *   GPRs RAX, RBX, RCX, RDX
	 *   XCR0
	 *   CPL
	 *
	 * VMMCALL allows the guest to provide extra registers. KVM also
	 * expects RSI for hypercalls, so include that, too.
	 *
	 * Copy their values to the appropriate location if supplied.
	 */
	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));

	vcpu->arch.regs[VCPU_REGS_RAX] = ghcb_get_rax_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RBX] = ghcb_get_rbx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RCX] = ghcb_get_rcx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RDX] = ghcb_get_rdx_if_valid(ghcb);
	vcpu->arch.regs[VCPU_REGS_RSI] = ghcb_get_rsi_if_valid(ghcb);

	svm->vmcb->save.cpl = ghcb_get_cpl_if_valid(ghcb);

	if (ghcb_xcr0_is_valid(ghcb)) {
		vcpu->arch.xcr0 = ghcb_get_xcr0(ghcb);
		kvm_update_cpuid_runtime(vcpu);
	}

	/* Copy the GHCB exit information into the VMCB fields */
	exit_code = ghcb_get_sw_exit_code(ghcb);
	control->exit_code = lower_32_bits(exit_code);
	control->exit_code_hi = upper_32_bits(exit_code);
	control->exit_info_1 = ghcb_get_sw_exit_info_1(ghcb);
	control->exit_info_2 = ghcb_get_sw_exit_info_2(ghcb);

	/* Copy the GHCB scratch area GPA */
	svm->sev_es.ghcb_sa_gpa = ghcb_get_sw_scratch(ghcb);

	/* Clear the valid entries fields */
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static int sev_es_validate_vmgexit(struct vcpu_svm *svm, u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm_host_map map;
	struct ghcb *ghcb;
	u64 reason;

	if (svm_map_ghcb(svm, &map))
		return -EFAULT;

	ghcb = map.hva;

	trace_kvm_vmgexit_enter(vcpu->vcpu_id, ghcb);

	/*
	 * Retrieve the exit code now even though it may not be marked valid
	 * as it could help with debugging.
	 */
	*exit_code = ghcb_get_sw_exit_code(ghcb);

	/* Only GHCB Usage code 0 is supported */
	if (ghcb->ghcb_usage) {
		reason = GHCB_ERR_INVALID_USAGE;
		goto vmgexit_err;
	}

	reason = GHCB_ERR_MISSING_INPUT;

	if (!ghcb_sw_exit_code_is_valid(ghcb) ||
	    !ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    !ghcb_sw_exit_info_2_is_valid(ghcb))
		goto vmgexit_err;

	switch (ghcb_get_sw_exit_code(ghcb)) {
	case SVM_EXIT_READ_DR7:
		break;
	case SVM_EXIT_WRITE_DR7:
		if (!ghcb_rax_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSC:
		break;
	case SVM_EXIT_RDPMC:
		if (!ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_CPUID:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		if (ghcb_get_rax(ghcb) == 0xd)
			if (!ghcb_xcr0_is_valid(ghcb))
				goto vmgexit_err;
		break;
	case SVM_EXIT_INVD:
		break;
	case SVM_EXIT_IOIO:
		if (ghcb_get_sw_exit_info_1(ghcb) & SVM_IOIO_STR_MASK) {
			if (!ghcb_sw_scratch_is_valid(ghcb))
				goto vmgexit_err;
		} else {
			if (!(ghcb_get_sw_exit_info_1(ghcb) & SVM_IOIO_TYPE_MASK))
				if (!ghcb_rax_is_valid(ghcb))
					goto vmgexit_err;
		}
		break;
	case SVM_EXIT_MSR:
		if (!ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		if (ghcb_get_sw_exit_info_1(ghcb)) {
			if (!ghcb_rax_is_valid(ghcb) ||
			    !ghcb_rdx_is_valid(ghcb))
				goto vmgexit_err;
		}
		break;
	case SVM_EXIT_VMMCALL:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_cpl_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSCP:
		break;
	case SVM_EXIT_WBINVD:
		break;
	case SVM_EXIT_MONITOR:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb) ||
		    !ghcb_rdx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_EXIT_MWAIT:
		if (!ghcb_rax_is_valid(ghcb) ||
		    !ghcb_rcx_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_MMIO_READ:
	case SVM_VMGEXIT_MMIO_WRITE:
		if (!ghcb_sw_scratch_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_AP_CREATION:
		if (!ghcb_rax_is_valid(ghcb))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
	case SVM_VMGEXIT_AP_HLT_LOOP:
	case SVM_VMGEXIT_AP_JUMP_TABLE:
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
	case SVM_VMGEXIT_HV_FEATURES:
	case SVM_VMGEXIT_PSC:
	case SVM_VMGEXIT_GUEST_REQUEST:
	case SVM_VMGEXIT_EXT_GUEST_REQUEST:
		break;
	default:
		reason = GHCB_ERR_INVALID_EVENT;
		goto vmgexit_err;
	}

	sev_es_sync_from_ghcb(svm, ghcb);

	svm_unmap_ghcb(svm, &map);
	return 0;

vmgexit_err:
	vcpu = &svm->vcpu;

	if (reason == GHCB_ERR_INVALID_USAGE) {
		vcpu_unimpl(vcpu, "vmgexit: ghcb usage %#x is not valid\n",
			    ghcb->ghcb_usage);
	} else if (reason == GHCB_ERR_INVALID_EVENT) {
		vcpu_unimpl(vcpu, "vmgexit: exit code %#llx is not valid\n",
			    *exit_code);
	} else {
		vcpu_unimpl(vcpu, "vmgexit: exit code %#llx input is not valid\n",
			    *exit_code);
		dump_ghcb(svm);
	}

	/* Clear the valid entries fields */
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));

	ghcb_set_sw_exit_info_1(ghcb, 2);
	ghcb_set_sw_exit_info_2(ghcb, reason);

	svm_unmap_ghcb(svm, &map);

	/* Resume the guest to "return" the error code. */
	return 1;
}

void sev_es_unmap_ghcb(struct vcpu_svm *svm)
{
	if (svm->sev_es.ghcb_sa_alloc_len >= 2)
		trace_kvm_sev_es_unmap_ghcb(svm->sev_es.ghcb_sa,
					    svm->sev_es.ghcb_sa_gpa,
					    svm->sev_es.ghcb_sa_len,
					    svm->sev_es.ghcb_sa_alloc_len,
					    svm->sev_es.ghcb_sa_sync,
					    svm->sev_es.ghcb_in_use,
					    ((u8 *)svm->sev_es.ghcb_sa)[0],
					    ((u8 *)svm->sev_es.ghcb_sa)[1]);
	else
		trace_kvm_sev_es_unmap_ghcb(svm->sev_es.ghcb_sa,
					    svm->sev_es.ghcb_sa_gpa,
					    svm->sev_es.ghcb_sa_len,
					    svm->sev_es.ghcb_sa_alloc_len,
					    svm->sev_es.ghcb_sa_sync,
					    svm->sev_es.ghcb_in_use,
					    0, 0);

	/* Clear any indication that the vCPU is in a type of AP Reset Hold */
	svm->sev_es.ap_reset_hold_type = AP_RESET_HOLD_NONE;

	if (!svm->sev_es.ghcb_in_use)
		return;

	sev_es_sync_to_ghcb(svm);

	svm->sev_es.ghcb_in_use = false;
}

void pre_sev_run(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	int asid = sev_get_asid(svm->vcpu.kvm);

	/* Assign the asid allocated with this SEV guest */
	svm->asid = asid;

	/*
	 * Flush guest TLB:
	 *
	 * 1) when different VMCB for the same ASID is to be run on the same host CPU.
	 * 2) or this VMCB was executed on different host CPU in previous VMRUNs.
	 */
	if (sd->sev_vmcbs[asid] == svm->vmcb &&
	    svm->vcpu.arch.last_vmentry_cpu == cpu)
		return;

	sd->sev_vmcbs[asid] = svm->vmcb;
	svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	vmcb_mark_dirty(svm->vmcb, VMCB_ASID);
}

#define GHCB_SCRATCH_AREA_LIMIT		(16ULL * PAGE_SIZE)
static int setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_scratch_beg, ghcb_scratch_end;
	u64 scratch_gpa_beg, scratch_gpa_end;

	scratch_gpa_beg = svm->sev_es.ghcb_sa_gpa;
	if (!scratch_gpa_beg) {
		pr_err("vmgexit: scratch gpa not provided\n");
		goto e_scratch;
	}

	scratch_gpa_end = scratch_gpa_beg + len;
	if (scratch_gpa_end < scratch_gpa_beg) {
		pr_err("vmgexit: scratch length (%#llx) not valid for scratch address (%#llx)\n",
		       len, scratch_gpa_beg);
		goto e_scratch;
	}

	if ((scratch_gpa_beg & PAGE_MASK) == control->ghcb_gpa) {
		/* Scratch area begins within GHCB */
		ghcb_scratch_beg = control->ghcb_gpa +
				   offsetof(struct ghcb, shared_buffer);
		ghcb_scratch_end = control->ghcb_gpa +
				   offsetof(struct ghcb, reserved_1);

		/*
		 * If the scratch area begins within the GHCB, it must be
		 * completely contained in the GHCB shared buffer area.
		 */
		if (scratch_gpa_beg < ghcb_scratch_beg ||
		    scratch_gpa_end > ghcb_scratch_end) {
			pr_err("vmgexit: scratch area is outside of GHCB shared buffer area (%#llx - %#llx)\n",
			       scratch_gpa_beg, scratch_gpa_end);
			goto e_scratch;
		}
		svm->sev_es.ghcb_sa_contained = true;
		svm->sev_es.ghcb_sa_offset = scratch_gpa_beg - ghcb_scratch_beg;
	} else {
		/*
		 * The guest memory must be read into a kernel buffer, so
		 * limit the size
		 */
		if (len > GHCB_SCRATCH_AREA_LIMIT) {
			pr_err("vmgexit: scratch area exceeds KVM limits (%#llx requested, %#llx limit)\n",
			       len, GHCB_SCRATCH_AREA_LIMIT);
			goto e_scratch;
		}
		svm->sev_es.ghcb_sa_contained = false;
	}

	if (svm->sev_es.ghcb_sa_alloc_len < len) {
		void *scratch_va = kvzalloc(len, GFP_KERNEL_ACCOUNT);

		if (!scratch_va)
			return -ENOMEM;

		/*
		 * Free the old scratch area and switch to using newly
		 * allocated.
		 */
		kvfree(svm->sev_es.ghcb_sa);

		svm->sev_es.ghcb_sa_alloc_len = len;
		svm->sev_es.ghcb_sa = scratch_va;
	}

	if (kvm_read_guest(svm->vcpu.kvm, scratch_gpa_beg, svm->sev_es.ghcb_sa, len)) {
		/* Unable to copy scratch area from guest */
		pr_err("vmgexit: kvm_read_guest for scratch area failed\n");
		return -EFAULT;
	}

	/*
	 * The operation will dictate whether the buffer needs to be synced
	 * before running the vCPU next time (i.e. a read was requested so
	 * the data must be written back to the guest memory).
	 */
	svm->sev_es.ghcb_sa_sync = sync;
	svm->sev_es.ghcb_sa_len = len;

	return 0;

e_scratch:
	svm_set_ghcb_sw_exit_info_1(&svm->vcpu, 2);
	svm_set_ghcb_sw_exit_info_2(&svm->vcpu, GHCB_ERR_INVALID_SCRATCH_AREA);

	return 1;
}

static void set_ghcb_msr_bits(struct vcpu_svm *svm, u64 value, u64 mask,
			      unsigned int pos)
{
	svm->vmcb->control.ghcb_gpa &= ~(mask << pos);
	svm->vmcb->control.ghcb_gpa |= (value & mask) << pos;
}

static u64 get_ghcb_msr_bits(struct vcpu_svm *svm, u64 mask, unsigned int pos)
{
	return (svm->vmcb->control.ghcb_gpa >> pos) & mask;
}

static void set_ghcb_msr(struct vcpu_svm *svm, u64 value)
{
	svm->vmcb->control.ghcb_gpa = value;
}

static int snp_rmptable_psmash(struct kvm *kvm, kvm_pfn_t pfn)
{
	pfn = pfn & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);

	return psmash(pfn);
}

static int snp_make_page_shared(struct kvm *kvm, gpa_t gpa, kvm_pfn_t pfn, int level)
{
	int rc, rmp_level;

	rc = snp_lookup_rmpentry(pfn, &rmp_level);
	if (rc < 0)
		return -EINVAL;

	/* If page is not assigned then do nothing */
	if (!rc)
		return 0;

	/*
	 * Is the page part of an existing 2MB RMP entry ? Split the 2MB into
	 * multiple of 4K-page before making the memory shared.
	 */
	if (level == PG_LEVEL_4K && rmp_level == PG_LEVEL_2M) {
		rc = snp_rmptable_psmash(kvm, pfn);
		if (rc)
			return rc;
	}

	return rmp_make_shared(pfn, level);
}

static int snp_check_and_build_npt(struct kvm_vcpu *vcpu, gpa_t gpa, int level)
{
	struct kvm *kvm = vcpu->kvm;
	int rc, npt_level;
	kvm_pfn_t pfn;

	/*
	 * Get the pfn and level for the gpa from the nested page table.
	 *
	 * If the tdp walk fails, then its safe to say that there is no
	 * valid mapping for this gpa. Create a fault to build the map.
	 */
	write_lock(&kvm->mmu_lock);
	rc = kvm_mmu_get_tdp_walk(vcpu, gpa, &pfn, &npt_level);
	write_unlock(&kvm->mmu_lock);
	if (!rc) {
		pfn = kvm_mmu_map_tdp_page(vcpu, gpa, PFERR_USER_MASK, level);
		if (is_error_noslot_pfn(pfn))
			return -EINVAL;
	}

	return 0;
}

static int snp_gpa_to_hva(struct kvm *kvm, gpa_t gpa, hva_t *hva)
{
	struct kvm_memory_slot *slot;
	gfn_t gfn = gpa_to_gfn(gpa);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	slot = gfn_to_memslot(kvm, gfn);
	if (!slot) {
		srcu_read_unlock(&kvm->srcu, idx);
		return -EINVAL;
	}

	/*
	 * Note, using the __gfn_to_hva_memslot() is not solely for performance,
	 * it's also necessary to avoid the "writable" check in __gfn_to_hva_many(),
	 * which will always fail on read-only memslots due to gfn_to_hva() assuming
	 * writes.
	 */
	*hva = __gfn_to_hva_memslot(slot, gfn);
	srcu_read_unlock(&kvm->srcu, idx);

	return 0;
}

static int __snp_handle_page_state_change(struct kvm_vcpu *vcpu, enum psc_op op, gpa_t gpa,
					  int level)
{
	struct kvm_sev_info *sev = &to_kvm_svm(vcpu->kvm)->sev_info;
	struct kvm *kvm = vcpu->kvm;
	int rc, npt_level;
	kvm_pfn_t pfn;
	gpa_t gpa_end;

	gpa_end = gpa + page_level_size(level);

	while (gpa < gpa_end) {
		/*
		 * If the gpa is not present in the NPT then build the NPT.
		 */
		rc = snp_check_and_build_npt(vcpu, gpa, level);
		if (rc)
			return PSC_UNDEF_ERR;

		if (op == SNP_PAGE_STATE_PRIVATE) {
			hva_t hva;

			if (snp_gpa_to_hva(kvm, gpa, &hva))
				return PSC_UNDEF_ERR;

			/*
			 * Verify that the hva range is registered. This enforcement is
			 * required to avoid the cases where a page is marked private
			 * in the RMP table but never gets cleanup during the VM
			 * termination path.
			 */
			mutex_lock(&kvm->lock);
			rc = is_hva_registered(kvm, hva, page_level_size(level));
			mutex_unlock(&kvm->lock);
			if (!rc)
				return PSC_UNDEF_ERR;

			/*
			 * Mark the userspace range unmerable before adding the pages
			 * in the RMP table.
			 */
			mmap_write_lock(kvm->mm);
			rc = snp_mark_unmergable(kvm, hva, page_level_size(level));
			mmap_write_unlock(kvm->mm);
			if (rc)
				return PSC_UNDEF_ERR;
		}

		spin_lock(&sev->psc_lock);

		write_lock(&kvm->mmu_lock);

		rc = kvm_mmu_get_tdp_walk(vcpu, gpa, &pfn, &npt_level);
		if (!rc) {
			/*
			 * This may happen if another vCPU unmapped the page
			 * before we acquire the lock. Retry the PSC.
			 */
			write_unlock(&kvm->mmu_lock);
			spin_unlock(&sev->psc_lock);
			return 0;
		}

		/*
		 * Adjust the level so that we don't go higher than the backing
		 * page level.
		 */
		level = min_t(size_t, level, npt_level);

		trace_kvm_snp_psc(vcpu->vcpu_id, pfn, gpa, op, level);

		switch (op) {
		case SNP_PAGE_STATE_SHARED:
			rc = snp_make_page_shared(kvm, gpa, pfn, level);
			break;
		case SNP_PAGE_STATE_PRIVATE:
			rc = rmp_make_private(pfn, gpa, level, sev->asid, false);
			break;
		default:
			rc = PSC_INVALID_ENTRY;
			break;
		}

		write_unlock(&kvm->mmu_lock);

		spin_unlock(&sev->psc_lock);

		if (rc) {
			pr_err_ratelimited("Error op %d gpa %llx pfn %llx level %d rc %d\n",
					   op, gpa, pfn, level, rc);
			return rc;
		}

		gpa = gpa + page_level_size(level);
	}

	return 0;
}

static inline unsigned long map_to_psc_vmgexit_code(int rc)
{
	switch (rc) {
	case PSC_INVALID_HDR:
		return ((1ul << 32) | 1);
	case PSC_INVALID_ENTRY:
		return ((1ul << 32) | 2);
	case RMPUPDATE_FAIL_OVERLAP:
		return ((3ul << 32) | 2);
	default: return (4ul << 32);
	}
}

static unsigned long snp_handle_page_state_change(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	int level, op, rc = PSC_UNDEF_ERR;
	struct snp_psc_desc *info;
	struct psc_entry *entry;
	u16 cur, end;
	gpa_t gpa;

	if (!sev_snp_guest(vcpu->kvm))
		return PSC_INVALID_HDR;

	if (setup_vmgexit_scratch(svm, true, sizeof(*info))) {
		pr_err("vmgexit: scratch area is not setup.\n");
		return PSC_INVALID_HDR;
	}

	info = (struct snp_psc_desc *)svm->sev_es.ghcb_sa;
	cur = info->hdr.cur_entry;
	end = info->hdr.end_entry;

	if (cur >= VMGEXIT_PSC_MAX_ENTRY ||
	    end >= VMGEXIT_PSC_MAX_ENTRY || cur > end)
		return PSC_INVALID_ENTRY;

	for (; cur <= end; cur++) {
		entry = &info->entries[cur];
		gpa = gfn_to_gpa(entry->gfn);
		level = RMP_TO_X86_PG_LEVEL(entry->pagesize);
		op = entry->operation;

		if (!IS_ALIGNED(gpa, page_level_size(level))) {
			rc = PSC_INVALID_ENTRY;
			goto out;
		}

		rc = __snp_handle_page_state_change(vcpu, op, gpa, level);
		if (rc)
			goto out;
	}

out:
	info->hdr.cur_entry = cur;
	return rc ? map_to_psc_vmgexit_code(rc) : 0;
}

static unsigned long snp_setup_guest_buf(struct vcpu_svm *svm,
					 struct sev_data_snp_guest_request *data,
					 gpa_t req_gpa, gpa_t resp_gpa)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	kvm_pfn_t req_pfn, resp_pfn;
	struct kvm_sev_info *sev;

	sev = &to_kvm_svm(kvm)->sev_info;

	if (!IS_ALIGNED(req_gpa, PAGE_SIZE) || !IS_ALIGNED(resp_gpa, PAGE_SIZE))
		return SEV_RET_INVALID_PARAM;

	req_pfn = gfn_to_pfn(kvm, gpa_to_gfn(req_gpa));
	if (is_error_noslot_pfn(req_pfn))
		return SEV_RET_INVALID_ADDRESS;

	resp_pfn = gfn_to_pfn(kvm, gpa_to_gfn(resp_gpa));
	if (is_error_noslot_pfn(resp_pfn))
		return SEV_RET_INVALID_ADDRESS;

	if (rmp_make_private(resp_pfn, 0, PG_LEVEL_4K, 0, true))
		return SEV_RET_INVALID_ADDRESS;

	data->gctx_paddr = __psp_pa(sev->snp_context);
	data->req_paddr = __sme_set(req_pfn << PAGE_SHIFT);
	data->res_paddr = __sme_set(resp_pfn << PAGE_SHIFT);

	return 0;
}

static void snp_cleanup_guest_buf(struct sev_data_snp_guest_request *data, unsigned long *rc)
{
	u64 pfn = __sme_clr(data->res_paddr) >> PAGE_SHIFT;
	int ret;

	ret = snp_page_reclaim(pfn);
	if (ret)
		*rc = SEV_RET_INVALID_ADDRESS;

	ret = rmp_make_shared(pfn, PG_LEVEL_4K);
	if (ret)
		*rc = SEV_RET_INVALID_ADDRESS;
}

static void snp_handle_guest_request(struct vcpu_svm *svm, gpa_t req_gpa, gpa_t resp_gpa)
{
	struct sev_data_snp_guest_request data = {0};
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_sev_info *sev;
	unsigned long rc;
	int err;

	if (!sev_snp_guest(vcpu->kvm)) {
		rc = SEV_RET_INVALID_GUEST;
		goto e_fail;
	}

	sev = &to_kvm_svm(kvm)->sev_info;

	mutex_lock(&sev->guest_req_lock);

	rc = snp_setup_guest_buf(svm, &data, req_gpa, resp_gpa);
	if (rc)
		goto unlock;

	rc = sev_issue_cmd(kvm, SEV_CMD_SNP_GUEST_REQUEST, &data, &err);
	if (rc)
		/* use the firmware error code */
		rc = err;

	snp_cleanup_guest_buf(&data, &rc);

unlock:
	mutex_unlock(&sev->guest_req_lock);

e_fail:
	svm_set_ghcb_sw_exit_info_2(vcpu, rc);
}

static void snp_handle_ext_guest_request(struct vcpu_svm *svm, gpa_t req_gpa, gpa_t resp_gpa)
{
	struct sev_data_snp_guest_request req = {0};
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm *kvm = vcpu->kvm;
	unsigned long data_npages;
	struct kvm_sev_info *sev;
	unsigned long rc, err;
	u64 data_gpa;

	if (!sev_snp_guest(vcpu->kvm)) {
		rc = SEV_RET_INVALID_GUEST;
		goto e_fail;
	}

	sev = &to_kvm_svm(kvm)->sev_info;

	data_gpa = vcpu->arch.regs[VCPU_REGS_RAX];
	data_npages = vcpu->arch.regs[VCPU_REGS_RBX];

	if (!IS_ALIGNED(data_gpa, PAGE_SIZE)) {
		rc = SEV_RET_INVALID_ADDRESS;
		goto e_fail;
	}

	/* Verify that requested blob will fit in certificate buffer */
	if ((data_npages << PAGE_SHIFT) > SEV_FW_BLOB_MAX_SIZE) {
		rc = SEV_RET_INVALID_PARAM;
		goto e_fail;
	}

	mutex_lock(&sev->guest_req_lock);

	rc = snp_setup_guest_buf(svm, &req, req_gpa, resp_gpa);
	if (rc)
		goto unlock;

	rc = snp_guest_ext_guest_request(&req, (unsigned long)sev->snp_certs_data,
					 &data_npages, &err);
	if (rc) {
		/*
		 * If buffer length is small then return the expected
		 * length in rbx.
		 */
		if (err == SNP_GUEST_REQ_INVALID_LEN)
			vcpu->arch.regs[VCPU_REGS_RBX] = data_npages;

		/* pass the firmware error code */
		rc = err;
		goto cleanup;
	}

	/* Copy the certificate blob in the guest memory */
	if (data_npages &&
	    kvm_write_guest(kvm, data_gpa, sev->snp_certs_data, data_npages << PAGE_SHIFT))
		rc = SEV_RET_INVALID_ADDRESS;

cleanup:
	snp_cleanup_guest_buf(&req, &rc);

unlock:
	mutex_unlock(&sev->guest_req_lock);

e_fail:
	svm_set_ghcb_sw_exit_info_2(vcpu, rc);
}

static int __sev_snp_update_protected_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	kvm_pfn_t pfn;
	hpa_t cur_pa;

	WARN_ON(!mutex_is_locked(&svm->sev_es.snp_vmsa_mutex));

	/* Save off the current VMSA PA for later checks */
	cur_pa = svm->sev_es.vmsa_pa;

	/* Mark the vCPU as offline and not runnable */
	vcpu->arch.pv.pv_unhalted = false;
	vcpu->arch.mp_state = KVM_MP_STATE_STOPPED;

	/* Clear use of the VMSA */
	svm->sev_es.vmsa_pa = INVALID_PAGE;
	svm->vmcb->control.vmsa_pa = INVALID_PAGE;

	if (cur_pa != __pa(svm->sev_es.vmsa) && VALID_PAGE(cur_pa)) {
		/*
		 * The svm->sev_es.vmsa_pa field holds the hypervisor physical
		 * address of the about to be replaced VMSA which will no longer
		 * be used or referenced, so un-pin it.
		 */
		kvm_release_pfn_dirty(__phys_to_pfn(cur_pa));
	}

	if (VALID_PAGE(svm->sev_es.snp_vmsa_gpa)) {
		/*
		 * The VMSA is referenced by the hypervisor physical address,
		 * so retrieve the PFN and pin it.
		 */
		pfn = gfn_to_pfn(vcpu->kvm, gpa_to_gfn(svm->sev_es.snp_vmsa_gpa));
		if (is_error_pfn(pfn))
			return -EINVAL;

		/* Use the new VMSA */
		svm->sev_es.vmsa_pa = pfn_to_hpa(pfn);
		svm->vmcb->control.vmsa_pa = svm->sev_es.vmsa_pa;

		/* Mark the vCPU as runnable */
		vcpu->arch.pv.pv_unhalted = false;
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

		svm->sev_es.snp_vmsa_gpa = INVALID_PAGE;
	}

	/*
	 * When replacing the VMSA during SEV-SNP AP creation,
	 * mark the VMCB dirty so that full state is always reloaded.
	 */
	vmcb_mark_all_dirty(svm->vmcb);

	return 0;
}

/*
 * Invoked as part of svm_vcpu_reset() processing of an init event.
 */
void sev_snp_init_protected_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	if (!sev_snp_guest(vcpu->kvm))
		return;

	mutex_lock(&svm->sev_es.snp_vmsa_mutex);

	if (!svm->sev_es.snp_ap_create)
		goto unlock;

	svm->sev_es.snp_ap_create = false;

	ret = __sev_snp_update_protected_guest_state(vcpu);
	if (ret)
		vcpu_unimpl(vcpu, "snp: AP state update on init failed\n");

unlock:
	mutex_unlock(&svm->sev_es.snp_vmsa_mutex);
}

static int sev_snp_ap_creation(struct vcpu_svm *svm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct kvm_vcpu *target_vcpu;
	struct vcpu_svm *target_svm;
	unsigned int request;
	unsigned int apic_id;
	bool kick;
	int ret;

	request = lower_32_bits(svm->vmcb->control.exit_info_1);
	apic_id = upper_32_bits(svm->vmcb->control.exit_info_1);

	/* Validate the APIC ID */
	target_vcpu = kvm_get_vcpu_by_id(vcpu->kvm, apic_id);
	if (!target_vcpu) {
		vcpu_unimpl(vcpu, "vmgexit: invalid AP APIC ID [%#x] from guest\n",
			    apic_id);
		return -EINVAL;
	}

	ret = 0;

	target_svm = to_svm(target_vcpu);

	/*
	 * We have a valid target vCPU, so the vCPU will be kicked unless the
	 * request is for CREATE_ON_INIT. For any errors at this stage, the
	 * kick will place the vCPU in an non-runnable state.
	 */
	kick = true;

	mutex_lock(&target_svm->sev_es.snp_vmsa_mutex);

	target_svm->sev_es.snp_vmsa_gpa = INVALID_PAGE;
	target_svm->sev_es.snp_ap_create = true;

	/* Interrupt injection mode shouldn't change for AP creation */
	if (request < SVM_VMGEXIT_AP_DESTROY) {
		u64 sev_features;

		sev_features = vcpu->arch.regs[VCPU_REGS_RAX];
		sev_features ^= sev->sev_features;
		if (sev_features & SVM_SEV_FEAT_INT_INJ_MODES) {
			vcpu_unimpl(vcpu, "vmgexit: invalid AP injection mode [%#lx] from guest\n",
				    vcpu->arch.regs[VCPU_REGS_RAX]);
			ret = -EINVAL;
			goto out;
		}
	}

	switch (request) {
	case SVM_VMGEXIT_AP_CREATE_ON_INIT:
		kick = false;
		fallthrough;
	case SVM_VMGEXIT_AP_CREATE:
		if (!page_address_valid(vcpu, svm->vmcb->control.exit_info_2)) {
			vcpu_unimpl(vcpu, "vmgexit: invalid AP VMSA address [%#llx] from guest\n",
				    svm->vmcb->control.exit_info_2);
			ret = -EINVAL;
			goto out;
		}

		target_svm->sev_es.snp_vmsa_gpa = svm->vmcb->control.exit_info_2;
		break;
	case SVM_VMGEXIT_AP_DESTROY:
		break;
	default:
		vcpu_unimpl(vcpu, "vmgexit: invalid AP creation request [%#x] from guest\n",
			    request);
		ret = -EINVAL;
		break;
	}

out:
	if (kick) {
		if (target_vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED)
			target_vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

		kvm_make_request(KVM_REQ_UPDATE_PROTECTED_GUEST_STATE, target_vcpu);
		kvm_vcpu_kick(target_vcpu);
	}

	mutex_unlock(&target_svm->sev_es.snp_vmsa_mutex);

	return ret;
}

static int sev_handle_vmgexit_msr_protocol(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	u64 ghcb_info;
	int ret = 1;

	ghcb_info = control->ghcb_gpa & GHCB_MSR_INFO_MASK;

	trace_kvm_vmgexit_msr_protocol_enter(svm->vcpu.vcpu_id,
					     control->ghcb_gpa);

	switch (ghcb_info) {
	case GHCB_MSR_SEV_INFO_REQ:
		set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
						    GHCB_VERSION_MIN,
						    sev_enc_bit));
		break;
	case GHCB_MSR_CPUID_REQ: {
		u64 cpuid_fn, cpuid_reg, cpuid_value;

		cpuid_fn = get_ghcb_msr_bits(svm,
					     GHCB_MSR_CPUID_FUNC_MASK,
					     GHCB_MSR_CPUID_FUNC_POS);

		/* Initialize the registers needed by the CPUID intercept */
		vcpu->arch.regs[VCPU_REGS_RAX] = cpuid_fn;
		vcpu->arch.regs[VCPU_REGS_RCX] = 0;

		ret = svm_invoke_exit_handler(vcpu, SVM_EXIT_CPUID);
		if (!ret) {
			/* Error, keep GHCB MSR value as-is */
			break;
		}

		cpuid_reg = get_ghcb_msr_bits(svm,
					      GHCB_MSR_CPUID_REG_MASK,
					      GHCB_MSR_CPUID_REG_POS);
		if (cpuid_reg == 0)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RAX];
		else if (cpuid_reg == 1)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RBX];
		else if (cpuid_reg == 2)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RCX];
		else
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RDX];

		set_ghcb_msr_bits(svm, cpuid_value,
				  GHCB_MSR_CPUID_VALUE_MASK,
				  GHCB_MSR_CPUID_VALUE_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_CPUID_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_AP_RESET_HOLD_REQ:
		svm->sev_es.ap_reset_hold_type = AP_RESET_HOLD_MSR_PROTO;
		ret = kvm_emulate_ap_reset_hold(&svm->vcpu);

		/*
		 * Preset the result to a non-SIPI return and then only set
		 * the result to non-zero when delivering a SIPI.
		 */
		set_ghcb_msr_bits(svm, 0,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_MASK,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_AP_RESET_HOLD_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	case GHCB_MSR_HV_FT_REQ: {
		set_ghcb_msr_bits(svm, GHCB_HV_FT_SUPPORTED,
				  GHCB_MSR_HV_FT_MASK, GHCB_MSR_HV_FT_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_HV_FT_RESP,
				  GHCB_MSR_INFO_MASK, GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_PREF_GPA_REQ: {
		set_ghcb_msr_bits(svm, GHCB_MSR_PREF_GPA_NONE, GHCB_MSR_GPA_VALUE_MASK,
				  GHCB_MSR_GPA_VALUE_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_PREF_GPA_RESP, GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_REG_GPA_REQ: {
		u64 gfn;

		gfn = get_ghcb_msr_bits(svm, GHCB_MSR_GPA_VALUE_MASK,
					GHCB_MSR_GPA_VALUE_POS);

		svm->sev_es.ghcb_registered_gpa = gfn_to_gpa(gfn);

		set_ghcb_msr_bits(svm, gfn, GHCB_MSR_GPA_VALUE_MASK,
				  GHCB_MSR_GPA_VALUE_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_REG_GPA_RESP, GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_PSC_REQ: {
		gfn_t gfn;
		int ret;
		enum psc_op op;

		gfn = get_ghcb_msr_bits(svm, GHCB_MSR_PSC_GFN_MASK, GHCB_MSR_PSC_GFN_POS);
		op = get_ghcb_msr_bits(svm, GHCB_MSR_PSC_OP_MASK, GHCB_MSR_PSC_OP_POS);

		ret = __snp_handle_page_state_change(vcpu, op, gfn_to_gpa(gfn), PG_LEVEL_4K);

		if (ret)
			set_ghcb_msr_bits(svm, GHCB_MSR_PSC_ERROR,
					  GHCB_MSR_PSC_ERROR_MASK, GHCB_MSR_PSC_ERROR_POS);
		else
			set_ghcb_msr_bits(svm, 0,
					  GHCB_MSR_PSC_ERROR_MASK, GHCB_MSR_PSC_ERROR_POS);

		set_ghcb_msr_bits(svm, 0, GHCB_MSR_PSC_RSVD_MASK, GHCB_MSR_PSC_RSVD_POS);
		set_ghcb_msr_bits(svm, GHCB_MSR_PSC_RESP, GHCB_MSR_INFO_MASK, GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_TERM_REQ: {
		u64 reason_set, reason_code;

		reason_set = get_ghcb_msr_bits(svm,
					       GHCB_MSR_TERM_REASON_SET_MASK,
					       GHCB_MSR_TERM_REASON_SET_POS);
		reason_code = get_ghcb_msr_bits(svm,
						GHCB_MSR_TERM_REASON_MASK,
						GHCB_MSR_TERM_REASON_POS);
		pr_info("SEV-ES guest requested termination: %#llx:%#llx\n",
			reason_set, reason_code);

		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SEV_TERM;
		vcpu->run->system_event.ndata = 1;
		vcpu->run->system_event.data[0] = control->ghcb_gpa;

		return 0;
	}
	default:
		/* Error, keep GHCB MSR value as-is */
		break;
	}

	trace_kvm_vmgexit_msr_protocol_exit(svm->vcpu.vcpu_id,
					    control->ghcb_gpa, ret);

	return ret;
}

int sev_handle_vmgexit(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_gpa, exit_code;
	int ret;

	/* Validate the GHCB */
	ghcb_gpa = control->ghcb_gpa;
	if (ghcb_gpa & GHCB_MSR_INFO_MASK)
		return sev_handle_vmgexit_msr_protocol(svm);

	if (!ghcb_gpa) {
		vcpu_unimpl(vcpu, "vmgexit: GHCB gpa is not set\n");

		/* Without a GHCB, just return right back to the guest */
		return 1;
	}

	/* SEV-SNP guest requires that the GHCB GPA must be registered */
	if (sev_snp_guest(svm->vcpu.kvm) && !ghcb_gpa_is_registered(svm, ghcb_gpa)) {
		vcpu_unimpl(&svm->vcpu, "vmgexit: GHCB GPA [%#llx] is not registered.\n", ghcb_gpa);
		return -EINVAL;
	}

	ret = sev_es_validate_vmgexit(svm, &exit_code);
	if (ret)
		return ret;

	svm->sev_es.ghcb_in_use = true;

	svm_set_ghcb_sw_exit_info_1(vcpu, 0);
	svm_set_ghcb_sw_exit_info_2(vcpu, 0);

	switch (exit_code) {
	case SVM_VMGEXIT_MMIO_READ:
		ret = setup_vmgexit_scratch(svm, true, control->exit_info_2);
		if (ret)
			break;

		ret = kvm_sev_es_mmio_read(vcpu,
					   control->exit_info_1,
					   control->exit_info_2,
					   svm->sev_es.ghcb_sa);
		break;
	case SVM_VMGEXIT_MMIO_WRITE:
		ret = setup_vmgexit_scratch(svm, false, control->exit_info_2);
		if (ret)
			break;

		ret = kvm_sev_es_mmio_write(vcpu,
					    control->exit_info_1,
					    control->exit_info_2,
					    svm->sev_es.ghcb_sa);
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
		ret = svm_invoke_exit_handler(vcpu, SVM_EXIT_IRET);
		break;
	case SVM_VMGEXIT_AP_HLT_LOOP:
		svm->sev_es.ap_reset_hold_type = AP_RESET_HOLD_NAE_EVENT;
		ret = kvm_emulate_ap_reset_hold(vcpu);
		break;
	case SVM_VMGEXIT_AP_JUMP_TABLE: {
		struct kvm_sev_info *sev = &to_kvm_svm(vcpu->kvm)->sev_info;

		switch (control->exit_info_1) {
		case 0:
			/* Set AP jump table address */
			sev->ap_jump_table = control->exit_info_2;
			break;
		case 1:
			/* Get AP jump table address */
			svm_set_ghcb_sw_exit_info_2(vcpu, sev->ap_jump_table);
			break;
		default:
			pr_err("svm: vmgexit: unsupported AP jump table request - exit_info_1=%#llx\n",
			       control->exit_info_1);
			svm_set_ghcb_sw_exit_info_1(vcpu, 2);
			svm_set_ghcb_sw_exit_info_2(vcpu, GHCB_ERR_INVALID_INPUT);
		}

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_HV_FEATURES: {
		svm_set_ghcb_sw_exit_info_2(vcpu, GHCB_HV_FT_SUPPORTED);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_PSC: {
		unsigned long rc;

		ret = 1;

		rc = snp_handle_page_state_change(svm);
		svm_set_ghcb_sw_exit_info_2(vcpu, rc);
		break;
	}
	case SVM_VMGEXIT_GUEST_REQUEST: {
		snp_handle_guest_request(svm, control->exit_info_1, control->exit_info_2);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_EXT_GUEST_REQUEST: {
		snp_handle_ext_guest_request(svm,
					     control->exit_info_1,
					     control->exit_info_2);

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_AP_CREATION:
		ret = sev_snp_ap_creation(svm);
		if (ret) {
			svm_set_ghcb_sw_exit_info_1(vcpu, 1);
			svm_set_ghcb_sw_exit_info_2(vcpu,
						    X86_TRAP_GP |
						    SVM_EVTINJ_TYPE_EXEPT |
						    SVM_EVTINJ_VALID);
		}

		ret = 1;
		break;
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
		vcpu_unimpl(vcpu,
			    "vmgexit: unsupported event - exit_info_1=%#llx, exit_info_2=%#llx\n",
			    control->exit_info_1, control->exit_info_2);
		ret = -EINVAL;
		break;
	default:
		ret = svm_invoke_exit_handler(vcpu, exit_code);
	}

	return ret;
}

int sev_es_string_io(struct vcpu_svm *svm, int size, unsigned int port, int in)
{
	int count;
	int bytes;
	int r;

	if (svm->vmcb->control.exit_info_2 > INT_MAX)
		return -EINVAL;

	count = svm->vmcb->control.exit_info_2;
	if (unlikely(check_mul_overflow(count, size, &bytes)))
		return -EINVAL;

	r = setup_vmgexit_scratch(svm, in, bytes);
	if (r) {
		pr_err("failed to setup vmgexit scratch\n");
		return r;
	}

	return kvm_sev_es_string_io(&svm->vcpu, size, port, svm->sev_es.ghcb_sa,
				    count, in);
}

static void sev_es_init_vmcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;

	svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ES_ENABLE;
	svm->vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK;

	/*
	 * An SEV-ES guest requires a VMSA area that is a separate from the
	 * VMCB page.
	 */
	svm->vmcb->control.vmsa_pa = svm->sev_es.vmsa_pa;

	/* Can't intercept CR register access, HV can't modify CR registers */
	svm_clr_intercept(svm, INTERCEPT_CR0_READ);
	svm_clr_intercept(svm, INTERCEPT_CR4_READ);
	svm_clr_intercept(svm, INTERCEPT_CR8_READ);
	svm_clr_intercept(svm, INTERCEPT_CR0_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR4_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR8_WRITE);

	svm_clr_intercept(svm, INTERCEPT_SELECTIVE_CR0);

	/* Track EFER/CR register changes */
	svm_set_intercept(svm, TRAP_EFER_WRITE);
	svm_set_intercept(svm, TRAP_CR0_WRITE);
	svm_set_intercept(svm, TRAP_CR4_WRITE);
	svm_set_intercept(svm, TRAP_CR8_WRITE);

	/* No support for enable_vmware_backdoor */
	clr_exception_intercept(svm, GP_VECTOR);

	/* Can't intercept XSETBV, HV can't modify XCR0 directly */
	svm_clr_intercept(svm, INTERCEPT_XSETBV);

	/* Clear intercepts on selected MSRs */
	set_msr_interception(vcpu, svm->msrpm, MSR_EFER, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_CR_PAT, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTTOIP, 1, 1);

	if (boot_cpu_has(X86_FEATURE_V_TSC_AUX) &&
	    (guest_cpuid_has(&svm->vcpu, X86_FEATURE_RDTSCP) ||
	     guest_cpuid_has(&svm->vcpu, X86_FEATURE_RDPID))) {
		set_msr_interception(vcpu, svm->msrpm, MSR_TSC_AUX, 1, 1);
		if (guest_cpuid_has(&svm->vcpu, X86_FEATURE_RDTSCP))
			svm_clr_intercept(svm, INTERCEPT_RDTSCP);
	}
}

void sev_init_vmcb(struct vcpu_svm *svm)
{
	svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ENABLE;
	clr_exception_intercept(svm, UD_VECTOR);

	if (sev_es_guest(svm->vcpu.kvm))
		sev_es_init_vmcb(svm);
}

void sev_es_vcpu_reset(struct vcpu_svm *svm)
{
	/*
	 * Set the GHCB MSR value as per the GHCB specification when emulating
	 * vCPU RESET for an SEV-ES guest.
	 */
	set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
					    GHCB_VERSION_MIN,
					    sev_enc_bit));

	mutex_init(&svm->sev_es.snp_vmsa_mutex);
}

void sev_es_prepare_switch_to_guest(struct sev_es_save_area *hostsa)
{
	/*
	 * As an SEV-ES guest, hardware will restore the host state on VMEXIT,
	 * of which one step is to perform a VMLOAD.  KVM performs the
	 * corresponding VMSAVE in svm_prepare_guest_switch for both
	 * traditional and SEV-ES guests.
	 */

	/* XCR0 is restored on VMEXIT, save the current host value */
	hostsa->xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	/* PKRU is restored on VMEXIT, save the current host value */
	hostsa->pkru = read_pkru();

	/* MSR_IA32_XSS is restored on VMEXIT, save the currnet host value */
	hostsa->xss = host_xss;
}

void sev_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	/* First SIPI: Use the values as initially set by the VMM */
	if (!svm->sev_es.received_first_sipi) {
		svm->sev_es.received_first_sipi = true;
		return;
	}

	/* Subsequent SIPI */
	switch (svm->sev_es.ap_reset_hold_type) {
	case AP_RESET_HOLD_NAE_EVENT:
		/*
		 * Return from an AP Reset Hold VMGEXIT, where the guest will
		 * set the CS and RIP. Set SW_EXIT_INFO_2 to a non-zero value.
		 */
		svm_set_ghcb_sw_exit_info_2(vcpu, 1);
		break;
	case AP_RESET_HOLD_MSR_PROTO:
		/*
		 * Return from an AP Reset Hold VMGEXIT, where the guest will
		 * set the CS and RIP. Set GHCB data field to a non-zero value.
		 */
		set_ghcb_msr_bits(svm, 1,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_MASK,
				  GHCB_MSR_AP_RESET_HOLD_RESULT_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_AP_RESET_HOLD_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	default:
		break;
	}
}

struct page *snp_safe_alloc_page(struct kvm_vcpu *vcpu)
{
	unsigned long pfn;
	struct page *p;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);

	/*
	 * Allocate an SNP safe page to workaround the SNP erratum where
	 * the CPU will incorrectly signal an RMP violation  #PF if a
	 * hugepage (2mb or 1gb) collides with the RMP entry of VMCB, VMSA
	 * or AVIC backing page. The recommeded workaround is to not use the
	 * hugepage.
	 *
	 * Allocate one extra page, use a page which is not 2mb aligned
	 * and free the other.
	 */
	p = alloc_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, 1);
	if (!p)
		return NULL;

	split_page(p, 1);

	pfn = page_to_pfn(p);
	if (IS_ALIGNED(__pfn_to_phys(pfn), PMD_SIZE)) {
		pfn++;
		__free_page(p);
	} else {
		__free_page(pfn_to_page(pfn + 1));
	}

	return pfn_to_page(pfn);
}

static bool is_pfn_range_shared(kvm_pfn_t start, kvm_pfn_t end)
{
	int level;

	while (end > start) {
		if (snp_lookup_rmpentry(start, &level) != 0)
			return false;
		start++;
	}

	return true;
}

void sev_rmp_page_level_adjust(struct kvm *kvm, kvm_pfn_t pfn, int *level)
{
	int rmp_level, assigned;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return;

	assigned = snp_lookup_rmpentry(pfn, &rmp_level);
	if (unlikely(assigned < 0))
		return;

	if (!assigned) {
		/*
		 * If all the pages are shared then no need to keep the RMP
		 * and NPT in sync.
		 */
		pfn = pfn & ~(PTRS_PER_PMD - 1);
		if (is_pfn_range_shared(pfn, pfn + PTRS_PER_PMD))
			return;
	}

	/*
	 * The hardware installs 2MB TLB entries to access to 1GB pages,
	 * therefore allow NPT to use 1GB pages when pfn was added as 2MB
	 * in the RMP table.
	 */
	if (rmp_level == PG_LEVEL_2M && (*level == PG_LEVEL_1G))
		return;

	/* Adjust the level to keep the NPT and RMP in sync */
	*level = min_t(size_t, *level, rmp_level);
}

int sev_post_map_gfn(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	int level;

	if (!sev_snp_guest(kvm))
		return 0;

	spin_lock(&sev->psc_lock);

	/* If pfn is not added as private then fail */
	if (snp_lookup_rmpentry(pfn, &level) == 1) {
		spin_unlock(&sev->psc_lock);
		pr_err_ratelimited("failed to map private gfn 0x%llx pfn 0x%llx\n", gfn, pfn);
		return -EBUSY;
	}

	return 0;
}

void sev_post_unmap_gfn(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	if (!sev_snp_guest(kvm))
		return;

	spin_unlock(&sev->psc_lock);
}

void handle_rmp_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa, u64 error_code)
{
	int rmp_level, npt_level, rc, assigned;
	struct kvm *kvm = vcpu->kvm;
	gfn_t gfn = gpa_to_gfn(gpa);
	bool need_psc = false;
	enum psc_op psc_op;
	kvm_pfn_t pfn;
	bool private;

	write_lock(&kvm->mmu_lock);

	if (unlikely(!kvm_mmu_get_tdp_walk(vcpu, gpa, &pfn, &npt_level)))
		goto unlock;

	assigned = snp_lookup_rmpentry(pfn, &rmp_level);
	if (unlikely(assigned < 0))
		goto unlock;

	private = !!(error_code & PFERR_GUEST_ENC_MASK);

	/*
	 * If the fault was due to size mismatch, or NPT and RMP page level's
	 * are not in sync, then use PSMASH to split the RMP entry into 4K.
	 */
	if ((error_code & PFERR_GUEST_SIZEM_MASK) ||
	    (npt_level == PG_LEVEL_4K && rmp_level == PG_LEVEL_2M && private)) {
		rc = snp_rmptable_psmash(kvm, pfn);
		if (rc)
			pr_err_ratelimited("psmash failed, gpa 0x%llx pfn 0x%llx rc %d\n",
					   gpa, pfn, rc);
		goto out;
	}

	/*
	 * If it's a private access, and the page is not assigned in the
	 * RMP table, create a new private RMP entry. This can happen if
	 * guest did not use the PSC VMGEXIT to transition the page state
	 * before the access.
	 */
	if (!assigned && private) {
		need_psc = 1;
		psc_op = SNP_PAGE_STATE_PRIVATE;
		goto out;
	}

	/*
	 * If it's a shared access, but the page is private in the RMP table
	 * then make the page shared in the RMP table. This can happen if
	 * the guest did not use the PSC VMGEXIT to transition the page
	 * state before the access.
	 */
	if (assigned && !private) {
		need_psc = 1;
		psc_op = SNP_PAGE_STATE_SHARED;
	}

out:
	write_unlock(&kvm->mmu_lock);

	if (need_psc)
		rc = __snp_handle_page_state_change(vcpu, psc_op, gpa, PG_LEVEL_4K);

	/*
	 * The fault handler has updated the RMP pagesize, zap the existing
	 * rmaps for large entry ranges so that nested page table gets rebuilt
	 * with the updated RMP pagesize.
	 */
	gfn = gpa_to_gfn(gpa) & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);
	kvm_zap_gfn_range(kvm, gfn, gfn + PTRS_PER_PMD);
	return;

unlock:
	write_unlock(&kvm->mmu_lock);
}
