// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Encrypted Virtualization (SEV) interface
 *
 * Copyright (C) 2016,2019 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/ccp.h>
#include <linux/firmware.h>
#include <linux/gfp.h>
#include <linux/cpufeature.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>

#include <asm/smp.h>
#include <asm/sev.h>
#include <asm/e820/types.h>

#include "psp-dev.h"
#include "sev-dev.h"

#define DEVICE_NAME		"sev"
#define SEV_FW_FILE		"amd/sev.fw"
#define SEV_FW_NAME_SIZE	64

/* Minimum firmware version required for the SEV-SNP support */
#define SNP_MIN_API_MAJOR	1
#define SNP_MIN_API_MINOR	51

static DEFINE_MUTEX(sev_cmd_mutex);
static struct sev_misc_dev *misc_dev;

static int psp_cmd_timeout = 100;
module_param(psp_cmd_timeout, int, 0644);
MODULE_PARM_DESC(psp_cmd_timeout, " default timeout value, in seconds, for PSP commands");

static int psp_probe_timeout = 5;
module_param(psp_probe_timeout, int, 0644);
MODULE_PARM_DESC(psp_probe_timeout, " default timeout value, in seconds, during PSP device probe");

static char *init_ex_path;
module_param(init_ex_path, charp, 0444);
MODULE_PARM_DESC(init_ex_path, " Path for INIT_EX data; if set try INIT_EX");

static bool psp_init_on_probe = true;
module_param(psp_init_on_probe, bool, 0444);
MODULE_PARM_DESC(psp_init_on_probe, "  if true, the PSP will be initialized on module init. Else the PSP will be initialized on the first command requiring it");

MODULE_FIRMWARE("amd/amd_sev_fam17h_model0xh.sbin"); /* 1st gen EPYC */
MODULE_FIRMWARE("amd/amd_sev_fam17h_model3xh.sbin"); /* 2nd gen EPYC */
MODULE_FIRMWARE("amd/amd_sev_fam19h_model0xh.sbin"); /* 3rd gen EPYC */

static bool psp_dead;
static int psp_timeout;

/* Trusted Memory Region (TMR):
 *   The TMR is a 1MB area that must be 1MB aligned.  Use the page allocator
 *   to allocate the memory, which will return aligned memory for the specified
 *   allocation order.
 */
#define SEV_ES_TMR_SIZE		(1024 * 1024)
static void *sev_es_tmr;

/* INIT_EX NV Storage:
 *   The NV Storage is a 32Kb area and must be 4Kb page aligned.  Use the page
 *   allocator to allocate the memory, which will return aligned memory for the
 *   specified allocation order.
 */
#define NV_LENGTH (32 * 1024)
static void *sev_init_ex_buffer;

/*
 * SEV_DATA_RANGE_LIST:
 *   Array containing range of pages that firmware transitions to HV-fixed
 *   page state.
 */
struct sev_data_range_list *snp_range_list;

/* When SEV-SNP is enabled the TMR needs to be 2MB aligned and 2MB size. */
#define SEV_SNP_ES_TMR_SIZE	(2 * 1024 * 1024)

static size_t sev_es_tmr_size = SEV_ES_TMR_SIZE;

static int __sev_do_cmd_locked(int cmd, void *data, int *psp_ret);
static int sev_do_cmd(int cmd, void *data, int *psp_ret);

static inline bool sev_version_greater_or_equal(u8 maj, u8 min)
{
	struct sev_device *sev = psp_master->sev_data;

	if (sev->api_major > maj)
		return true;

	if (sev->api_major == maj && sev->api_minor >= min)
		return true;

	return false;
}

static void sev_irq_handler(int irq, void *data, unsigned int status)
{
	struct sev_device *sev = data;
	int reg;

	/* Check if it is command completion: */
	if (!(status & SEV_CMD_COMPLETE))
		return;

	/* Check if it is SEV command completion: */
	reg = ioread32(sev->io_regs + sev->vdata->cmdresp_reg);
	if (reg & PSP_CMDRESP_RESP) {
		sev->int_rcvd = 1;
		wake_up(&sev->int_queue);
	}
}

static int sev_wait_cmd_ioc(struct sev_device *sev,
			    unsigned int *reg, unsigned int timeout)
{
	int ret;

	ret = wait_event_timeout(sev->int_queue,
			sev->int_rcvd, timeout * HZ);
	if (!ret)
		return -ETIMEDOUT;

	*reg = ioread32(sev->io_regs + sev->vdata->cmdresp_reg);

	return 0;
}

static int sev_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_INIT:			return sizeof(struct sev_data_init);
	case SEV_CMD_INIT_EX:                   return sizeof(struct sev_data_init_ex);
	case SEV_CMD_SNP_SHUTDOWN_EX:		return sizeof(struct sev_data_snp_shutdown_ex);
	case SEV_CMD_SNP_INIT_EX:		return sizeof(struct sev_data_snp_init_ex);
	case SEV_CMD_PLATFORM_STATUS:		return sizeof(struct sev_user_data_status);
	case SEV_CMD_PEK_CSR:			return sizeof(struct sev_data_pek_csr);
	case SEV_CMD_PEK_CERT_IMPORT:		return sizeof(struct sev_data_pek_cert_import);
	case SEV_CMD_PDH_CERT_EXPORT:		return sizeof(struct sev_data_pdh_cert_export);
	case SEV_CMD_LAUNCH_START:		return sizeof(struct sev_data_launch_start);
	case SEV_CMD_LAUNCH_UPDATE_DATA:	return sizeof(struct sev_data_launch_update_data);
	case SEV_CMD_LAUNCH_UPDATE_VMSA:	return sizeof(struct sev_data_launch_update_vmsa);
	case SEV_CMD_LAUNCH_FINISH:		return sizeof(struct sev_data_launch_finish);
	case SEV_CMD_LAUNCH_MEASURE:		return sizeof(struct sev_data_launch_measure);
	case SEV_CMD_ACTIVATE:			return sizeof(struct sev_data_activate);
	case SEV_CMD_DEACTIVATE:		return sizeof(struct sev_data_deactivate);
	case SEV_CMD_DECOMMISSION:		return sizeof(struct sev_data_decommission);
	case SEV_CMD_GUEST_STATUS:		return sizeof(struct sev_data_guest_status);
	case SEV_CMD_DBG_DECRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_DBG_ENCRYPT:		return sizeof(struct sev_data_dbg);
	case SEV_CMD_SEND_START:		return sizeof(struct sev_data_send_start);
	case SEV_CMD_SEND_UPDATE_DATA:		return sizeof(struct sev_data_send_update_data);
	case SEV_CMD_SEND_UPDATE_VMSA:		return sizeof(struct sev_data_send_update_vmsa);
	case SEV_CMD_SEND_FINISH:		return sizeof(struct sev_data_send_finish);
	case SEV_CMD_RECEIVE_START:		return sizeof(struct sev_data_receive_start);
	case SEV_CMD_RECEIVE_FINISH:		return sizeof(struct sev_data_receive_finish);
	case SEV_CMD_RECEIVE_UPDATE_DATA:	return sizeof(struct sev_data_receive_update_data);
	case SEV_CMD_RECEIVE_UPDATE_VMSA:	return sizeof(struct sev_data_receive_update_vmsa);
	case SEV_CMD_LAUNCH_UPDATE_SECRET:	return sizeof(struct sev_data_launch_secret);
	case SEV_CMD_DOWNLOAD_FIRMWARE:		return sizeof(struct sev_data_download_firmware);
	case SEV_CMD_GET_ID:			return sizeof(struct sev_data_get_id);
	case SEV_CMD_ATTESTATION_REPORT:	return sizeof(struct sev_data_attestation_report);
	case SEV_CMD_SEND_CANCEL:		return sizeof(struct sev_data_send_cancel);
	case SEV_CMD_SNP_GCTX_CREATE:		return sizeof(struct sev_data_snp_gctx_create);
	case SEV_CMD_SNP_LAUNCH_START:		return sizeof(struct sev_data_snp_launch_start);
	case SEV_CMD_SNP_LAUNCH_UPDATE:		return sizeof(struct sev_data_snp_launch_update);
	case SEV_CMD_SNP_ACTIVATE:		return sizeof(struct sev_data_snp_activate);
	case SEV_CMD_SNP_DECOMMISSION:		return sizeof(struct sev_data_snp_decommission);
	case SEV_CMD_SNP_PAGE_RECLAIM:		return sizeof(struct sev_data_snp_page_reclaim);
	case SEV_CMD_SNP_GUEST_STATUS:		return sizeof(struct sev_data_snp_guest_status);
	case SEV_CMD_SNP_LAUNCH_FINISH:		return sizeof(struct sev_data_snp_launch_finish);
	case SEV_CMD_SNP_DBG_DECRYPT:		return sizeof(struct sev_data_snp_dbg);
	case SEV_CMD_SNP_DBG_ENCRYPT:		return sizeof(struct sev_data_snp_dbg);
	case SEV_CMD_SNP_PAGE_UNSMASH:		return sizeof(struct sev_data_snp_page_unsmash);
	case SEV_CMD_SNP_PLATFORM_STATUS:	return sizeof(struct sev_data_snp_platform_status_buf);
	case SEV_CMD_SNP_GUEST_REQUEST:		return sizeof(struct sev_data_snp_guest_request);
	case SEV_CMD_SNP_CONFIG:		return sizeof(struct sev_user_data_snp_config);
	default:				return 0;
	}

	return 0;
}

static void snp_leak_pages(unsigned long pfn, unsigned int npages)
{
	WARN(1, "psc failed, pfn 0x%lx pages %d (leaking)\n", pfn, npages);
	while (npages--) {
		memory_failure(pfn, 0);
		dump_rmpentry(pfn);
		pfn++;
	}
}

static int snp_reclaim_pages(unsigned long pfn, unsigned int npages, bool locked)
{
	struct sev_data_snp_page_reclaim data;
	int ret, err, i, n = 0;

	for (i = 0; i < npages; i++) {
		memset(&data, 0, sizeof(data));
		data.paddr = pfn << PAGE_SHIFT;

		if (locked)
			ret = __sev_do_cmd_locked(SEV_CMD_SNP_PAGE_RECLAIM, &data, &err);
		else
			ret = sev_do_cmd(SEV_CMD_SNP_PAGE_RECLAIM, &data, &err);
		if (ret)
			goto cleanup;

		ret = rmp_make_shared(pfn, PG_LEVEL_4K);
		if (ret)
			goto cleanup;

		pfn++;
		n++;
	}

	return 0;

cleanup:
	/*
	 * If failed to reclaim the page then page is no longer safe to
	 * be released, leak it.
	 */
	snp_leak_pages(pfn, npages - n);
	return ret;
}

static inline int rmp_make_firmware(unsigned long pfn, int level)
{
	return rmp_make_private(pfn, 0, level, 0, true);
}

static int snp_set_rmp_state(unsigned long paddr, unsigned int npages, bool to_fw, bool locked,
			     bool need_reclaim)
{
	unsigned long pfn = __sme_clr(paddr) >> PAGE_SHIFT; /* Cbit maybe set in the paddr */
	int rc, n = 0, i;

	for (i = 0; i < npages; i++) {
		if (to_fw)
			rc = rmp_make_firmware(pfn, PG_LEVEL_4K);
		else
			rc = need_reclaim ? snp_reclaim_pages(pfn, 1, locked) :
					    rmp_make_shared(pfn, PG_LEVEL_4K);
		if (rc)
			goto cleanup;

		pfn++;
		n++;
	}

	return 0;

cleanup:
	/* Try unrolling the firmware state changes */
	if (to_fw) {
		/*
		 * Reclaim the pages which were already changed to the
		 * firmware state.
		 */
		snp_reclaim_pages(paddr >> PAGE_SHIFT, n, locked);

		return rc;
	}

	/*
	 * If failed to change the page state to shared, then its not safe
	 * to release the page back to the system, leak it.
	 */
	snp_leak_pages(pfn, npages - n);

	return rc;
}

static struct page *__snp_alloc_firmware_pages(gfp_t gfp_mask, int order, bool locked)
{
	unsigned long npages = 1ul << order, paddr;
	struct sev_device *sev;
	struct page *page;

	if (!psp_master || !psp_master->sev_data)
		return NULL;

	page = alloc_pages(gfp_mask, order);
	if (!page)
		return NULL;

	/* If SEV-SNP is initialized then add the page in RMP table. */
	sev = psp_master->sev_data;
	if (!sev->snp_inited)
		return page;

	paddr = __pa((unsigned long)page_address(page));
	if (snp_set_rmp_state(paddr, npages, true, locked, false))
		return NULL;

	return page;
}

void *snp_alloc_firmware_page(gfp_t gfp_mask)
{
	struct page *page;

	page = __snp_alloc_firmware_pages(gfp_mask, 0, false);

	return page ? page_address(page) : NULL;
}
EXPORT_SYMBOL_GPL(snp_alloc_firmware_page);

static void __snp_free_firmware_pages(struct page *page, int order, bool locked)
{
	unsigned long paddr, npages = 1ul << order;
	struct sev_device *sev;

	if (!page)
		return;

	paddr = __pa((unsigned long)page_address(page));
	sev = psp_master->sev_data;
	if (sev->snp_inited && snp_set_rmp_state(paddr, npages, false, locked, true))

		return;

	__free_pages(page, order);
}

void snp_free_firmware_page(void *addr)
{
	if (!addr)
		return;

	__snp_free_firmware_pages(virt_to_page(addr), 0, false);
}
EXPORT_SYMBOL(snp_free_firmware_page);

static void *sev_fw_alloc(unsigned long len)
{
	struct page *page;

	page = __snp_alloc_firmware_pages(GFP_KERNEL, get_order(len), false);
	if (!page)
		return NULL;

	return page_address(page);
}

static struct file *open_file_as_root(const char *filename, int flags, umode_t mode)
{
	struct file *fp;
	struct path root;
	struct cred *cred;
	const struct cred *old_cred;

	task_lock(&init_task);
	get_fs_root(init_task.fs, &root);
	task_unlock(&init_task);

	cred = prepare_creds();
	if (!cred)
		return ERR_PTR(-ENOMEM);
	cred->fsuid = GLOBAL_ROOT_UID;
	old_cred = override_creds(cred);

	fp = file_open_root(&root, filename, flags, mode);
	path_put(&root);

	revert_creds(old_cred);

	return fp;
}

static int sev_read_init_ex_file(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct file *fp;
	ssize_t nread;

	lockdep_assert_held(&sev_cmd_mutex);

	if (!sev_init_ex_buffer)
		return -EOPNOTSUPP;

	fp = open_file_as_root(init_ex_path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		int ret = PTR_ERR(fp);

		dev_err(sev->dev,
			"SEV: could not open %s for read, error %d\n",
			init_ex_path, ret);
		return ret;
	}

	nread = kernel_read(fp, sev_init_ex_buffer, NV_LENGTH, NULL);
	if (nread != NV_LENGTH) {
		dev_err(sev->dev,
			"SEV: failed to read %u bytes to non volatile memory area, ret %ld\n",
			NV_LENGTH, nread);
		return -EIO;
	}

	dev_dbg(sev->dev, "SEV: read %ld bytes from NV file\n", nread);
	filp_close(fp, NULL);

	return 0;
}

static void sev_write_init_ex_file(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct file *fp;
	loff_t offset = 0;
	ssize_t nwrite;

	lockdep_assert_held(&sev_cmd_mutex);

	if (!sev_init_ex_buffer)
		return;

	fp = open_file_as_root(init_ex_path, O_CREAT | O_WRONLY, 0600);
	if (IS_ERR(fp)) {
		dev_err(sev->dev,
			"SEV: could not open file for write, error %ld\n",
			PTR_ERR(fp));
		return;
	}

	nwrite = kernel_write(fp, sev_init_ex_buffer, NV_LENGTH, &offset);
	vfs_fsync(fp, 0);
	filp_close(fp, NULL);

	if (nwrite != NV_LENGTH) {
		dev_err(sev->dev,
			"SEV: failed to write %u bytes to non volatile memory area, ret %ld\n",
			NV_LENGTH, nwrite);
		return;
	}

	dev_dbg(sev->dev, "SEV: write successful to NV file\n");
}

static void sev_write_init_ex_file_if_required(int cmd_id)
{
	lockdep_assert_held(&sev_cmd_mutex);

	if (!sev_init_ex_buffer)
		return;

	/*
	 * Only a few platform commands modify the SPI/NV area, but none of the
	 * non-platform commands do. Only INIT(_EX), PLATFORM_RESET, PEK_GEN,
	 * PEK_CERT_IMPORT, and PDH_GEN do.
	 */
	switch (cmd_id) {
	case SEV_CMD_FACTORY_RESET:
	case SEV_CMD_INIT_EX:
	case SEV_CMD_PDH_GEN:
	case SEV_CMD_PEK_CERT_IMPORT:
	case SEV_CMD_PEK_GEN:
		break;
	default:
		return;
	}

	sev_write_init_ex_file();
}

static int alloc_snp_host_map(struct sev_device *sev)
{
	struct page *page;
	int i;

	for (i = 0; i < MAX_SNP_HOST_MAP_BUFS; i++) {
		struct snp_host_map *map = &sev->snp_host_map[i];

		memset(map, 0, sizeof(*map));

		page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(SEV_FW_BLOB_MAX_SIZE));
		if (!page)
			return -ENOMEM;

		map->host = page_address(page);
	}

	return 0;
}

static void free_snp_host_map(struct sev_device *sev)
{
	int i;

	for (i = 0; i < MAX_SNP_HOST_MAP_BUFS; i++) {
		struct snp_host_map *map = &sev->snp_host_map[i];

		if (map->host) {
			__free_pages(virt_to_page(map->host), get_order(SEV_FW_BLOB_MAX_SIZE));
			memset(map, 0, sizeof(*map));
		}
	}
}

static int map_firmware_writeable(u64 *paddr, u32 len, bool guest, struct snp_host_map *map)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;

	map->active = false;

	if (!paddr || !len)
		return 0;

	map->paddr = *paddr;
	map->len = len;

	/* If paddr points to a guest memory then change the page state to firmwware. */
	if (guest) {
		if (snp_set_rmp_state(*paddr, npages, true, true, false))
			return -EFAULT;

		goto done;
	}

	if (!map->host)
		return -ENOMEM;

	/* Check if the pre-allocated buffer can be used to fullfil the request. */
	if (len > SEV_FW_BLOB_MAX_SIZE)
		return -EINVAL;

	/* Transition the pre-allocated buffer to the firmware state. */
	if (snp_set_rmp_state(__pa(map->host), npages, true, true, false))
		return -EFAULT;

	/* Set the paddr to use pre-allocated firmware buffer */
	*paddr = __psp_pa(map->host);

done:
	map->active = true;
	return 0;
}

static int unmap_firmware_writeable(u64 *paddr, u32 len, bool guest, struct snp_host_map *map)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;

	if (!map->active)
		return 0;

	/* If paddr points to a guest memory then restore the page state to hypervisor. */
	if (guest) {
		if (snp_set_rmp_state(*paddr, npages, false, true, true))
			return -EFAULT;

		goto done;
	}

	/*
	 * Transition the pre-allocated buffer to hypervisor state before the access.
	 *
	 * This is because while changing the page state to firmware, the kernel unmaps
	 * the pages from the direct map, and to restore the direct map we must
	 * transition the pages to shared state.
	 */
	if (snp_set_rmp_state(__pa(map->host), npages, false, true, true))
		return -EFAULT;

	/* Copy the response data firmware buffer to the callers buffer. */
	memcpy(__va(__sme_clr(map->paddr)), map->host, min_t(size_t, len, map->len));
	*paddr = map->paddr;

done:
	map->active = false;
	return 0;
}

static bool sev_legacy_cmd_buf_writable(int cmd)
{
	switch (cmd) {
	case SEV_CMD_PLATFORM_STATUS:
	case SEV_CMD_GUEST_STATUS:
	case SEV_CMD_LAUNCH_START:
	case SEV_CMD_RECEIVE_START:
	case SEV_CMD_LAUNCH_MEASURE:
	case SEV_CMD_SEND_START:
	case SEV_CMD_SEND_UPDATE_DATA:
	case SEV_CMD_SEND_UPDATE_VMSA:
	case SEV_CMD_PEK_CSR:
	case SEV_CMD_PDH_CERT_EXPORT:
	case SEV_CMD_GET_ID:
	case SEV_CMD_ATTESTATION_REPORT:
		return true;
	default:
		return false;
	}
}

#define prep_buffer(name, addr, len, guest, map) \
	func(&((typeof(name *))cmd_buf)->addr, ((typeof(name *))cmd_buf)->len, guest, map)

static int __snp_cmd_buf_copy(int cmd, void *cmd_buf, bool to_fw, int fw_err)
{
	int (*func)(u64 *paddr, u32 len, bool guest, struct snp_host_map *map);
	struct sev_device *sev = psp_master->sev_data;
	bool from_fw = !to_fw;

	/*
	 * After the command is completed, change the command buffer memory to
	 * hypervisor state.
	 *
	 * The immutable bit is automatically cleared by the firmware, so
	 * no not need to reclaim the page.
	 */
	if (from_fw && sev_legacy_cmd_buf_writable(cmd)) {
		if (snp_set_rmp_state(__pa(cmd_buf), 1, false, true, false))
			return -EFAULT;

		/* No need to go further if firmware failed to execute command. */
		if (fw_err)
			return 0;
	}

	if (to_fw)
		func = map_firmware_writeable;
	else
		func = unmap_firmware_writeable;

	/*
	 * A command buffer may contains a system physical address. If the address
	 * points to a host memory then use an intermediate firmware page otherwise
	 * change the page state in the RMP table.
	 */
	switch (cmd) {
	case SEV_CMD_PDH_CERT_EXPORT:
		if (prep_buffer(struct sev_data_pdh_cert_export, pdh_cert_address,
				pdh_cert_len, false, &sev->snp_host_map[0]))
			goto err;
		if (prep_buffer(struct sev_data_pdh_cert_export, cert_chain_address,
				cert_chain_len, false, &sev->snp_host_map[1]))
			goto err;
		break;
	case SEV_CMD_GET_ID:
		if (prep_buffer(struct sev_data_get_id, address, len,
				false, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_PEK_CSR:
		if (prep_buffer(struct sev_data_pek_csr, address, len,
				false, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_LAUNCH_UPDATE_DATA:
		if (prep_buffer(struct sev_data_launch_update_data, address, len,
				true, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_LAUNCH_UPDATE_VMSA:
		if (prep_buffer(struct sev_data_launch_update_vmsa, address, len,
				true, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_LAUNCH_MEASURE:
		if (prep_buffer(struct sev_data_launch_measure, address, len,
				false, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_LAUNCH_UPDATE_SECRET:
		if (prep_buffer(struct sev_data_launch_secret, guest_address, guest_len,
				true, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_DBG_DECRYPT:
		if (prep_buffer(struct sev_data_dbg, dst_addr, len, false,
				&sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_DBG_ENCRYPT:
		if (prep_buffer(struct sev_data_dbg, dst_addr, len, true,
				&sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_ATTESTATION_REPORT:
		if (prep_buffer(struct sev_data_attestation_report, address, len,
				false, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_SEND_START:
		if (prep_buffer(struct sev_data_send_start, session_address,
				session_len, false, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_SEND_UPDATE_DATA:
		if (prep_buffer(struct sev_data_send_update_data, hdr_address, hdr_len,
				false, &sev->snp_host_map[0]))
			goto err;
		if (prep_buffer(struct sev_data_send_update_data, trans_address,
				trans_len, false, &sev->snp_host_map[1]))
			goto err;
		break;
	case SEV_CMD_SEND_UPDATE_VMSA:
		if (prep_buffer(struct sev_data_send_update_vmsa, hdr_address, hdr_len,
				false, &sev->snp_host_map[0]))
			goto err;
		if (prep_buffer(struct sev_data_send_update_vmsa, trans_address,
				trans_len, false, &sev->snp_host_map[1]))
			goto err;
		break;
	case SEV_CMD_RECEIVE_UPDATE_DATA:
		if (prep_buffer(struct sev_data_receive_update_data, guest_address,
				guest_len, true, &sev->snp_host_map[0]))
			goto err;
		break;
	case SEV_CMD_RECEIVE_UPDATE_VMSA:
		if (prep_buffer(struct sev_data_receive_update_vmsa, guest_address,
				guest_len, true, &sev->snp_host_map[0]))
			goto err;
		break;
	default:
		break;
	}

	/* The command buffer need to be in the firmware state. */
	if (to_fw && sev_legacy_cmd_buf_writable(cmd)) {
		if (snp_set_rmp_state(__pa(cmd_buf), 1, true, true, false))
			return -EFAULT;
	}

	return 0;

err:
	return -EINVAL;
}

static inline bool need_firmware_copy(int cmd)
{
	struct sev_device *sev = psp_master->sev_data;

	/* After SNP is INIT'ed, the behavior of legacy SEV command is changed. */
	return ((cmd < SEV_CMD_SNP_INIT) && sev->snp_inited) ? true : false;
}

static int snp_aware_copy_to_firmware(int cmd, void *data)
{
	return __snp_cmd_buf_copy(cmd, data, true, 0);
}

static int snp_aware_copy_from_firmware(int cmd, void *data, int fw_err)
{
	return __snp_cmd_buf_copy(cmd, data, false, fw_err);
}

static int __sev_do_cmd_locked(int cmd, void *data, int *psp_ret)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret = 0;
	void *cmd_buf;
	int buf_len;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	if (psp_dead)
		return -EBUSY;

	sev = psp->sev_data;

	buf_len = sev_cmd_buffer_len(cmd);
	if (WARN_ON_ONCE(!data != !buf_len))
		return -EINVAL;

	/*
	 * Copy the incoming data to driver's scratch buffer as __pa() will not
	 * work for some memory, e.g. vmalloc'd addresses, and @data may not be
	 * physically contiguous.
	 */
	if (data) {
		if (sev->cmd_buf_active > 2)
			return -EBUSY;

		cmd_buf = sev->cmd_buf_active ? sev->cmd_buf_backup : sev->cmd_buf;

		memcpy(cmd_buf, data, buf_len);
		sev->cmd_buf_active++;

		/*
		 * The behavior of the SEV-legacy commands is altered when the
		 * SNP firmware is in the INIT state.
		 */
		if (need_firmware_copy(cmd) && snp_aware_copy_to_firmware(cmd, sev->cmd_buf))
			return -EFAULT;
	} else {
		cmd_buf = sev->cmd_buf;
	}

	/* Get the physical address of the command buffer */
	phys_lsb = data ? lower_32_bits(__psp_pa(cmd_buf)) : 0;
	phys_msb = data ? upper_32_bits(__psp_pa(cmd_buf)) : 0;

	dev_dbg(sev->dev, "sev command id %#x buffer 0x%08x%08x timeout %us\n",
		cmd, phys_msb, phys_lsb, psp_timeout);

	print_hex_dump_debug("(in):  ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     buf_len, false);

	iowrite32(phys_lsb, sev->io_regs + sev->vdata->cmdbuff_addr_lo_reg);
	iowrite32(phys_msb, sev->io_regs + sev->vdata->cmdbuff_addr_hi_reg);

	sev->int_rcvd = 0;

	reg = cmd;
	reg <<= SEV_CMDRESP_CMD_SHIFT;
	reg |= SEV_CMDRESP_IOC;
	iowrite32(reg, sev->io_regs + sev->vdata->cmdresp_reg);

	/* wait for command completion */
	ret = sev_wait_cmd_ioc(sev, &reg, psp_timeout);
	if (ret) {
		if (psp_ret)
			*psp_ret = 0;

		dev_err(sev->dev, "sev command %#x timed out, disabling PSP\n", cmd);
		psp_dead = true;

		return ret;
	}

	psp_timeout = psp_cmd_timeout;

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(sev->dev, "sev command %#x failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	} else {
		sev_write_init_ex_file_if_required(cmd);
	}

	/*
	 * Copy potential output from the PSP back to data.  Do this even on
	 * failure in case the caller wants to glean something from the error.
	 */
	if (data) {
		/*
		 * Restore the page state after the command completes.
		 */
		if (need_firmware_copy(cmd) &&
		    snp_aware_copy_from_firmware(cmd, cmd_buf, ret))
			return -EFAULT;

		memcpy(data, cmd_buf, buf_len);
		sev->cmd_buf_active--;
	}

	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			     buf_len, false);

	return ret;
}

static int sev_do_cmd(int cmd, void *data, int *psp_ret)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_do_cmd_locked(cmd, data, psp_ret);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int __sev_init_locked(int *error)
{
	struct sev_data_init data;

	memset(&data, 0, sizeof(data));
	if (sev_es_tmr) {
		/*
		 * Do not include the encryption mask on the physical
		 * address of the TMR (firmware should clear it anyway).
		 */
		data.tmr_address = __pa(sev_es_tmr);

		data.flags |= SEV_INIT_FLAGS_SEV_ES;
		data.tmr_len = sev_es_tmr_size;
	}

	return __sev_do_cmd_locked(SEV_CMD_INIT, &data, error);
}

static int __sev_init_ex_locked(int *error)
{
	struct sev_data_init_ex data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.length = sizeof(data);
	data.nv_address = __psp_pa(sev_init_ex_buffer);
	data.nv_len = NV_LENGTH;

	ret = sev_read_init_ex_file();
	if (ret)
		return ret;

	if (sev_es_tmr) {
		/*
		 * Do not include the encryption mask on the physical
		 * address of the TMR (firmware should clear it anyway).
		 */
		data.tmr_address = __pa(sev_es_tmr);

		data.flags |= SEV_INIT_FLAGS_SEV_ES;
		data.tmr_len = sev_es_tmr_size;
	}

	return __sev_do_cmd_locked(SEV_CMD_INIT_EX, &data, error);
}

static int __sev_platform_init_locked(int *error)
{
	struct psp_device *psp = psp_master;
	struct sev_device *sev;
	int rc, psp_ret = -1;
	int (*init_function)(int *error);

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	if (sev->state == SEV_STATE_INIT)
		return 0;

	init_function = sev_init_ex_buffer ? __sev_init_ex_locked :
			__sev_init_locked;
	rc = init_function(&psp_ret);
	if (rc && psp_ret == SEV_RET_SECURE_DATA_INVALID) {
		/*
		 * Initialization command returned an integrity check failure
		 * status code, meaning that firmware load and validation of SEV
		 * related persistent data has failed. Retrying the
		 * initialization function should succeed by replacing the state
		 * with a reset state.
		 */
		dev_err(sev->dev, "SEV: retrying INIT command because of SECURE_DATA_INVALID error. Retrying once to reset PSP SEV state.");
		rc = init_function(&psp_ret);
	}
	if (error)
		*error = psp_ret;

	if (rc)
		return rc;

	sev->state = SEV_STATE_INIT;

	/* Prepare for first SEV guest launch after INIT */
	wbinvd_on_all_cpus();
	rc = __sev_do_cmd_locked(SEV_CMD_DF_FLUSH, NULL, error);
	if (rc)
		return rc;

	dev_dbg(sev->dev, "SEV firmware initialized\n");

	dev_info(sev->dev, "SEV API:%d.%d build:%d\n", sev->api_major,
		 sev->api_minor, sev->build);

	return 0;
}

int sev_platform_init(int *error)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_platform_init_locked(error);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(sev_platform_init);

static int __sev_platform_shutdown_locked(int *error)
{
	struct sev_device *sev = psp_master->sev_data;
	int ret;

	if (sev->state == SEV_STATE_UNINIT)
		return 0;

	ret = __sev_do_cmd_locked(SEV_CMD_SHUTDOWN, NULL, error);
	if (ret)
		return ret;

	sev->state = SEV_STATE_UNINIT;
	dev_dbg(sev->dev, "SEV firmware shutdown\n");

	return ret;
}

static int sev_platform_shutdown(int *error)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_platform_shutdown_locked(NULL);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int sev_get_platform_state(int *state, int *error)
{
	struct sev_user_data_status data;
	int rc;

	rc = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, error);
	if (rc)
		return rc;

	*state = data.state;
	return rc;
}

static int sev_ioctl_do_reset(struct sev_issue_cmd *argp, bool writable)
{
	int state, rc;

	if (!writable)
		return -EPERM;

	/*
	 * The SEV spec requires that FACTORY_RESET must be issued in
	 * UNINIT state. Before we go further lets check if any guest is
	 * active.
	 *
	 * If FW is in WORKING state then deny the request otherwise issue
	 * SHUTDOWN command do INIT -> UNINIT before issuing the FACTORY_RESET.
	 *
	 */
	rc = sev_get_platform_state(&state, &argp->error);
	if (rc)
		return rc;

	if (state == SEV_STATE_WORKING)
		return -EBUSY;

	if (state == SEV_STATE_INIT) {
		rc = __sev_platform_shutdown_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(SEV_CMD_FACTORY_RESET, NULL, &argp->error);
}

static int sev_ioctl_do_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_user_data_status data;
	int ret;

	ret = __sev_do_cmd_locked(SEV_CMD_PLATFORM_STATUS, &data, &argp->error);
	if (ret)
		return ret;

	if (copy_to_user((void __user *)argp->data, &data, sizeof(data)))
		ret = -EFAULT;

	return ret;
}

static int sev_ioctl_do_pek_pdh_gen(int cmd, struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	int rc;

	if (!writable)
		return -EPERM;

	if (sev->state == SEV_STATE_UNINIT) {
		rc = __sev_platform_init_locked(&argp->error);
		if (rc)
			return rc;
	}

	return __sev_do_cmd_locked(cmd, NULL, &argp->error);
}

static int sev_ioctl_do_pek_csr(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pek_csr input;
	struct sev_data_pek_csr data;
	void __user *input_address;
	void *blob = NULL;
	int ret;

	if (!writable)
		return -EPERM;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* userspace wants to query CSR length */
	if (!input.address || !input.length)
		goto cmd;

	/* allocate a physically contiguous buffer to store the CSR blob */
	input_address = (void __user *)input.address;
	if (input.length > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	blob = kmalloc(input.length, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	data.address = __psp_pa(blob);
	data.len = input.length;

cmd:
	if (sev->state == SEV_STATE_UNINIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_blob;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CSR, &data, &argp->error);

	 /* If we query the CSR length, FW responded with expected data. */
	input.length = data.len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_blob;
	}

	if (blob) {
		if (copy_to_user(input_address, blob, input.length))
			ret = -EFAULT;
	}

e_free_blob:
	kfree(blob);
	return ret;
}

void *psp_copy_user_blob(u64 uaddr, u32 len)
{
	if (!uaddr || !len)
		return ERR_PTR(-EINVAL);

	/* verify that blob length does not exceed our limit */
	if (len > SEV_FW_BLOB_MAX_SIZE)
		return ERR_PTR(-EINVAL);

	return memdup_user((void __user *)uaddr, len);
}
EXPORT_SYMBOL_GPL(psp_copy_user_blob);

static int sev_get_api_version(void)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_status status;
	int error = 0, ret;

	ret = sev_platform_status(&status, &error);
	if (ret) {
		dev_err(sev->dev,
			"SEV: failed to get status. Error: %#x\n", error);
		return 1;
	}

	sev->api_major = status.api_major;
	sev->api_minor = status.api_minor;
	sev->build = status.build;
	sev->state = status.state;

	return 0;
}

static int sev_get_firmware(struct device *dev,
			    const struct firmware **firmware)
{
	char fw_name_specific[SEV_FW_NAME_SIZE];
	char fw_name_subset[SEV_FW_NAME_SIZE];

	snprintf(fw_name_specific, sizeof(fw_name_specific),
		 "amd/amd_sev_fam%.2xh_model%.2xh.sbin",
		 boot_cpu_data.x86, boot_cpu_data.x86_model);

	snprintf(fw_name_subset, sizeof(fw_name_subset),
		 "amd/amd_sev_fam%.2xh_model%.1xxh.sbin",
		 boot_cpu_data.x86, (boot_cpu_data.x86_model & 0xf0) >> 4);

	/* Check for SEV FW for a particular model.
	 * Ex. amd_sev_fam17h_model00h.sbin for Family 17h Model 00h
	 *
	 * or
	 *
	 * Check for SEV FW common to a subset of models.
	 * Ex. amd_sev_fam17h_model0xh.sbin for
	 *     Family 17h Model 00h -- Family 17h Model 0Fh
	 *
	 * or
	 *
	 * Fall-back to using generic name: sev.fw
	 */
	if ((firmware_request_nowarn(firmware, fw_name_specific, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, fw_name_subset, dev) >= 0) ||
	    (firmware_request_nowarn(firmware, SEV_FW_FILE, dev) >= 0))
		return 0;

	return -ENOENT;
}

/* Don't fail if SEV FW couldn't be updated. Continue with existing SEV FW */
static int sev_update_firmware(struct device *dev)
{
	struct sev_data_download_firmware *data;
	const struct firmware *firmware;
	int ret, error, order;
	struct page *p;
	u64 data_size;

	if (sev_get_firmware(dev, &firmware) == -ENOENT) {
		dev_dbg(dev, "No SEV firmware file present\n");
		return -1;
	}

	/*
	 * SEV FW expects the physical address given to it to be 32
	 * byte aligned. Memory allocated has structure placed at the
	 * beginning followed by the firmware being passed to the SEV
	 * FW. Allocate enough memory for data structure + alignment
	 * padding + SEV FW.
	 */
	data_size = ALIGN(sizeof(struct sev_data_download_firmware), 32);

	order = get_order(firmware->size + data_size);
	p = alloc_pages(GFP_KERNEL, order);
	if (!p) {
		ret = -1;
		goto fw_err;
	}

	/*
	 * Copy firmware data to a kernel allocated contiguous
	 * memory region.
	 */
	data = page_address(p);
	memcpy(page_address(p) + data_size, firmware->data, firmware->size);

	data->address = __psp_pa(page_address(p) + data_size);
	data->len = firmware->size;

	ret = sev_do_cmd(SEV_CMD_DOWNLOAD_FIRMWARE, data, &error);
	if (ret)
		dev_dbg(dev, "Failed to update SEV firmware: %#x\n", error);
	else
		dev_info(dev, "SEV firmware update successful\n");

	__free_pages(p, order);

fw_err:
	release_firmware(firmware);

	return ret;
}

static void snp_set_hsave_pa(void *arg)
{
	wrmsrl(MSR_VM_HSAVE_PA, 0);
}

static int snp_filter_reserved_mem_regions(struct resource *rs, void *arg)
{
	struct sev_data_range_list *range_list = arg;
	struct sev_data_range *range = &range_list->ranges[range_list->num_elements];
	size_t size;

	if ((range_list->num_elements * sizeof(struct sev_data_range) +
	     sizeof(struct sev_data_range_list)) > PAGE_SIZE)
	       return -E2BIG;

	switch(rs->desc) {
		case E820_TYPE_RESERVED:
		case E820_TYPE_PMEM:
		case E820_TYPE_ACPI:
			range->base = rs->start & PAGE_MASK;
			size = (rs->end + 1) - rs->start;
			range->page_count = size >> PAGE_SHIFT;
			range_list->num_elements++;
			break;
		default:
			break;
	}

	return 0;
}

static int __sev_snp_init_locked(int *error)
{
	struct psp_device *psp = psp_master;
	struct sev_data_snp_init_ex data;
	struct sev_device *sev;
	int rc = 0;

	if (!psp || !psp->sev_data)
		return -ENODEV;

	sev = psp->sev_data;

	if (sev->snp_inited)
		return 0;

	/*
	 * The SNP_INIT requires the MSR_VM_HSAVE_PA must be set to 0h
	 * across all cores.
	 */
	on_each_cpu(snp_set_hsave_pa, NULL, 1);

	/*
	 * Starting in SNP firmware v1.52, the SNP_INIT_EX command takes a list of
	 * system physical address ranges to convert into the HV-fixed page states
	 * during the RMP initialization.  For instance, the memory that UEFI
	 * reserves should be included in the range list. This allows system
	 * components that occasionally write to memory (e.g. logging to UEFI
	 * reserved regions) to not fail due to RMP initialization and SNP enablement.
	 */
	if (sev_version_greater_or_equal(SNP_MIN_API_MAJOR, 52)) {
		/*
		 * Firmware checks that the pages containing the ranges enumerated
		 * in the RANGES structure are either in the Default page state or in the
		 * firmware page state.
		 */
		snp_range_list = sev_fw_alloc(PAGE_SIZE);
		if (!snp_range_list) {
			dev_err(sev->dev,
				"SEV: SNP_INIT_EX range list memory allocation failed\n");
			return -ENOMEM;
		}

		memset(snp_range_list, 0, PAGE_SIZE);

		/*
		 * Retrieve all reserved memory regions setup by UEFI from the e820 memory map
		 * to be setup as HV-fixed pages.
		 */

		rc = walk_iomem_res_desc(IORES_DESC_NONE, IORESOURCE_MEM, 0, ~0, snp_range_list, snp_filter_reserved_mem_regions);
		if (rc) {
			dev_err(sev->dev,
				"SEV: SNP_INIT_EX walk_iomem_res_desc failed rc = %d\n", rc);
			return rc;
		}

		memset(&data, 0, sizeof(data));
		data.init_rmp = 1;
		data.list_paddr_en = 1;
		data.list_paddr = __pa(snp_range_list);

		/* Issue the SNP_INIT_EX firmware command. */
		rc = __sev_do_cmd_locked(SEV_CMD_SNP_INIT_EX, &data, error);
		if (rc)
			return rc;
	} else {
		/* Issue the SNP_INIT firmware command. */
		rc = __sev_do_cmd_locked(SEV_CMD_SNP_INIT, NULL, error);
		if (rc)
			return rc;
	}

	/* Prepare for first SNP guest launch after INIT */
	wbinvd_on_all_cpus();
	rc = __sev_do_cmd_locked(SEV_CMD_SNP_DF_FLUSH, NULL, error);
	if (rc)
		return rc;

	sev->snp_inited = true;
	dev_dbg(sev->dev, "SEV-SNP firmware initialized\n");

	sev_es_tmr_size = SEV_SNP_ES_TMR_SIZE;

	return rc;
}

int sev_snp_init(int *error)
{
	int rc;

	if (!cpu_feature_enabled(X86_FEATURE_SEV_SNP))
		return -ENODEV;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_snp_init_locked(error);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}
EXPORT_SYMBOL_GPL(sev_snp_init);

static int __sev_snp_shutdown_locked(int *error)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_data_snp_shutdown_ex data;
	int ret;

	if (!sev->snp_inited)
		return 0;

	memset(&data, 0, sizeof(data));
	data.length = sizeof(data);
	data.iommu_snp_shutdown = 1;

	/* Free the memory used for caching the certificate data */
	kfree(sev->snp_certs_data);
	sev->snp_certs_data = NULL;

	/* SHUTDOWN requires the DF_FLUSH */
	wbinvd_on_all_cpus();
	__sev_do_cmd_locked(SEV_CMD_SNP_DF_FLUSH, NULL, NULL);

	ret = __sev_do_cmd_locked(SEV_CMD_SNP_SHUTDOWN_EX, &data, error);
	if (ret) {
		dev_err(sev->dev, "SEV-SNP firmware shutdown failed\n");
		return ret;
	}

	sev->snp_inited = false;
	dev_dbg(sev->dev, "SEV-SNP firmware shutdown\n");

	return ret;
}

static int sev_snp_shutdown(int *error)
{
	int rc;

	mutex_lock(&sev_cmd_mutex);
	rc = __sev_snp_shutdown_locked(NULL);
	mutex_unlock(&sev_cmd_mutex);

	return rc;
}

static int sev_ioctl_do_pek_import(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pek_cert_import input;
	struct sev_data_pek_cert_import data;
	void *pek_blob, *oca_blob;
	int ret;

	if (!writable)
		return -EPERM;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* copy PEK certificate blobs from userspace */
	pek_blob = psp_copy_user_blob(input.pek_cert_address, input.pek_cert_len);
	if (IS_ERR(pek_blob))
		return PTR_ERR(pek_blob);

	data.reserved = 0;
	data.pek_cert_address = __psp_pa(pek_blob);
	data.pek_cert_len = input.pek_cert_len;

	/* copy PEK certificate blobs from userspace */
	oca_blob = psp_copy_user_blob(input.oca_cert_address, input.oca_cert_len);
	if (IS_ERR(oca_blob)) {
		ret = PTR_ERR(oca_blob);
		goto e_free_pek;
	}

	data.oca_cert_address = __psp_pa(oca_blob);
	data.oca_cert_len = input.oca_cert_len;

	/* If platform is not in INIT state then transition it to INIT */
	if (sev->state != SEV_STATE_INIT) {
		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			goto e_free_oca;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_PEK_CERT_IMPORT, &data, &argp->error);

e_free_oca:
	kfree(oca_blob);
e_free_pek:
	kfree(pek_blob);
	return ret;
}

static int sev_ioctl_do_get_id2(struct sev_issue_cmd *argp)
{
	struct sev_user_data_get_id2 input;
	struct sev_data_get_id data;
	void __user *input_address;
	void *id_blob = NULL;
	int ret;

	/* SEV GET_ID is available from SEV API v0.16 and up */
	if (!sev_version_greater_or_equal(0, 16))
		return -ENOTSUPP;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	input_address = (void __user *)input.address;

	if (input.address && input.length) {
		id_blob = kmalloc(input.length, GFP_KERNEL);
		if (!id_blob)
			return -ENOMEM;

		data.address = __psp_pa(id_blob);
		data.len = input.length;
	} else {
		data.address = 0;
		data.len = 0;
	}

	ret = __sev_do_cmd_locked(SEV_CMD_GET_ID, &data, &argp->error);

	/*
	 * Firmware will return the length of the ID value (either the minimum
	 * required length or the actual length written), return it to the user.
	 */
	input.length = data.len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free;
	}

	if (id_blob) {
		if (copy_to_user(input_address, id_blob, data.len)) {
			ret = -EFAULT;
			goto e_free;
		}
	}

e_free:
	kfree(id_blob);

	return ret;
}

static int sev_ioctl_do_get_id(struct sev_issue_cmd *argp)
{
	struct sev_data_get_id *data;
	u64 data_size, user_size;
	void *id_blob, *mem;
	int ret;

	/* SEV GET_ID available from SEV API v0.16 and up */
	if (!sev_version_greater_or_equal(0, 16))
		return -ENOTSUPP;

	/* SEV FW expects the buffer it fills with the ID to be
	 * 8-byte aligned. Memory allocated should be enough to
	 * hold data structure + alignment padding + memory
	 * where SEV FW writes the ID.
	 */
	data_size = ALIGN(sizeof(struct sev_data_get_id), 8);
	user_size = sizeof(struct sev_user_data_get_id);

	mem = kzalloc(data_size + user_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	data = mem;
	id_blob = mem + data_size;

	data->address = __psp_pa(id_blob);
	data->len = user_size;

	ret = __sev_do_cmd_locked(SEV_CMD_GET_ID, data, &argp->error);
	if (!ret) {
		if (copy_to_user((void __user *)argp->data, id_blob, data->len))
			ret = -EFAULT;
	}

	kfree(mem);

	return ret;
}

static int sev_ioctl_do_pdh_export(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_pdh_cert_export input;
	void *pdh_blob = NULL, *cert_blob = NULL;
	struct sev_data_pdh_cert_export data;
	void __user *input_cert_chain_address;
	void __user *input_pdh_cert_address;
	int ret;

	/* If platform is not in INIT state then transition it to INIT. */
	if (sev->state != SEV_STATE_INIT) {
		if (!writable)
			return -EPERM;

		ret = __sev_platform_init_locked(&argp->error);
		if (ret)
			return ret;
	}

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	memset(&data, 0, sizeof(data));

	/* Userspace wants to query the certificate length. */
	if (!input.pdh_cert_address ||
	    !input.pdh_cert_len ||
	    !input.cert_chain_address)
		goto cmd;

	input_pdh_cert_address = (void __user *)input.pdh_cert_address;
	input_cert_chain_address = (void __user *)input.cert_chain_address;

	/* Allocate a physically contiguous buffer to store the PDH blob. */
	if (input.pdh_cert_len > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	/* Allocate a physically contiguous buffer to store the cert chain blob. */
	if (input.cert_chain_len > SEV_FW_BLOB_MAX_SIZE)
		return -EFAULT;

	pdh_blob = kmalloc(input.pdh_cert_len, GFP_KERNEL);
	if (!pdh_blob)
		return -ENOMEM;

	data.pdh_cert_address = __psp_pa(pdh_blob);
	data.pdh_cert_len = input.pdh_cert_len;

	cert_blob = kmalloc(input.cert_chain_len, GFP_KERNEL);
	if (!cert_blob) {
		ret = -ENOMEM;
		goto e_free_pdh;
	}

	data.cert_chain_address = __psp_pa(cert_blob);
	data.cert_chain_len = input.cert_chain_len;

cmd:
	ret = __sev_do_cmd_locked(SEV_CMD_PDH_CERT_EXPORT, &data, &argp->error);

	/* If we query the length, FW responded with expected data. */
	input.cert_chain_len = data.cert_chain_len;
	input.pdh_cert_len = data.pdh_cert_len;

	if (copy_to_user((void __user *)argp->data, &input, sizeof(input))) {
		ret = -EFAULT;
		goto e_free_cert;
	}

	if (pdh_blob) {
		if (copy_to_user(input_pdh_cert_address,
				 pdh_blob, input.pdh_cert_len)) {
			ret = -EFAULT;
			goto e_free_cert;
		}
	}

	if (cert_blob) {
		if (copy_to_user(input_cert_chain_address,
				 cert_blob, input.cert_chain_len))
			ret = -EFAULT;
	}

e_free_cert:
	kfree(cert_blob);
e_free_pdh:
	kfree(pdh_blob);
	return ret;
}

static int sev_ioctl_snp_platform_status(struct sev_issue_cmd *argp)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_data_snp_platform_status_buf buf;
	struct page *status_page;
	void *data;
	int ret;

	if (!sev->snp_inited || !argp->data)
		return -EINVAL;

	status_page = alloc_page(GFP_KERNEL_ACCOUNT);
	if (!status_page)
		return -ENOMEM;

	data = page_address(status_page);
	if (snp_set_rmp_state(__pa(data), 1, true, true, false)) {
		__free_pages(status_page, 0);
		return -EFAULT;
	}

	buf.status_paddr = __psp_pa(data);
	ret = __sev_do_cmd_locked(SEV_CMD_SNP_PLATFORM_STATUS, &buf, &argp->error);

	/* Change the page state before accessing it */
	if (snp_set_rmp_state(__pa(data), 1, false, true, true)) {
		snp_leak_pages(__pa(data) >> PAGE_SHIFT, 1);
		return -EFAULT;
	}

	if (ret)
		goto cleanup;

	if (copy_to_user((void __user *)argp->data, data,
			 sizeof(struct sev_user_data_snp_status)))
		ret = -EFAULT;

cleanup:
	__free_pages(status_page, 0);
	return ret;
}

static int sev_ioctl_snp_get_config(struct sev_issue_cmd *argp)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_ext_snp_config input;
	int ret;

	if (!sev->snp_inited || !argp->data)
		return -EINVAL;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* Copy the TCB version programmed through the SET_CONFIG to userspace */
	if (input.config_address) {
		if (copy_to_user((void * __user)input.config_address,
				 &sev->snp_config, sizeof(struct sev_user_data_snp_config)))
			return -EFAULT;
	}

	/* Copy the extended certs programmed through the SNP_SET_CONFIG */
	if (input.certs_address && sev->snp_certs_data) {
		if (input.certs_len < sev->snp_certs_len) {
			/* Return the certs length to userspace */
			input.certs_len = sev->snp_certs_len;

			ret = -ENOSR;
			goto e_done;
		}

		if (copy_to_user((void * __user)input.certs_address,
				 sev->snp_certs_data, sev->snp_certs_len))
			return -EFAULT;
	}

	ret = 0;

e_done:
	if (copy_to_user((void __user *)argp->data, &input, sizeof(input)))
		ret = -EFAULT;

	return ret;
}

static int sev_ioctl_snp_set_config(struct sev_issue_cmd *argp, bool writable)
{
	struct sev_device *sev = psp_master->sev_data;
	struct sev_user_data_ext_snp_config input;
	struct sev_user_data_snp_config config;
	void *certs = NULL;
	int ret = 0;

	if (!sev->snp_inited || !argp->data)
		return -EINVAL;

	if (!writable)
		return -EPERM;

	if (copy_from_user(&input, (void __user *)argp->data, sizeof(input)))
		return -EFAULT;

	/* Copy the certs from userspace */
	if (input.certs_address) {
		if (!input.certs_len || !IS_ALIGNED(input.certs_len, PAGE_SIZE))
			return -EINVAL;

		certs = psp_copy_user_blob(input.certs_address, input.certs_len);
		if (IS_ERR(certs))
			return PTR_ERR(certs);
	}

	/* Issue the PSP command to update the TCB version using the SNP_CONFIG. */
	if (input.config_address) {
		if (copy_from_user(&config,
				   (void __user *)input.config_address, sizeof(config))) {
			ret = -EFAULT;
			goto e_free;
		}

		ret = __sev_do_cmd_locked(SEV_CMD_SNP_CONFIG, &config, &argp->error);
		if (ret)
			goto e_free;

		memcpy(&sev->snp_config, &config, sizeof(config));
	}

	/*
	 * If the new certs are passed then cache it else free the old certs.
	 */
	if (certs) {
		kfree(sev->snp_certs_data);
		sev->snp_certs_data = certs;
		sev->snp_certs_len = input.certs_len;
	} else {
		kfree(sev->snp_certs_data);
		sev->snp_certs_data = NULL;
		sev->snp_certs_len = 0;
	}

	return 0;

e_free:
	kfree(certs);
	return ret;
}

static long sev_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sev_issue_cmd input;
	int ret = -EFAULT;
	bool writable = file->f_mode & FMODE_WRITE;

	if (!psp_master || !psp_master->sev_data)
		return -ENODEV;

	if (ioctl != SEV_ISSUE_CMD)
		return -EINVAL;

	if (copy_from_user(&input, argp, sizeof(struct sev_issue_cmd)))
		return -EFAULT;

	if (input.cmd > SEV_MAX)
		return -EINVAL;

	mutex_lock(&sev_cmd_mutex);

	switch (input.cmd) {

	case SEV_FACTORY_RESET:
		ret = sev_ioctl_do_reset(&input, writable);
		break;
	case SEV_PLATFORM_STATUS:
		ret = sev_ioctl_do_platform_status(&input);
		break;
	case SEV_PEK_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PEK_GEN, &input, writable);
		break;
	case SEV_PDH_GEN:
		ret = sev_ioctl_do_pek_pdh_gen(SEV_CMD_PDH_GEN, &input, writable);
		break;
	case SEV_PEK_CSR:
		ret = sev_ioctl_do_pek_csr(&input, writable);
		break;
	case SEV_PEK_CERT_IMPORT:
		ret = sev_ioctl_do_pek_import(&input, writable);
		break;
	case SEV_PDH_CERT_EXPORT:
		ret = sev_ioctl_do_pdh_export(&input, writable);
		break;
	case SEV_GET_ID:
		pr_warn_once("SEV_GET_ID command is deprecated, use SEV_GET_ID2\n");
		ret = sev_ioctl_do_get_id(&input);
		break;
	case SEV_GET_ID2:
		ret = sev_ioctl_do_get_id2(&input);
		break;
	case SNP_PLATFORM_STATUS:
		ret = sev_ioctl_snp_platform_status(&input);
		break;
	case SNP_SET_EXT_CONFIG:
		ret = sev_ioctl_snp_set_config(&input, writable);
		break;
	case SNP_GET_EXT_CONFIG:
		ret = sev_ioctl_snp_get_config(&input);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;
out:
	mutex_unlock(&sev_cmd_mutex);

	return ret;
}

static const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

int sev_platform_status(struct sev_user_data_status *data, int *error)
{
	return sev_do_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_do_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_do_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_do_cmd(SEV_CMD_DF_FLUSH, NULL, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);

int snp_guest_decommission(struct sev_data_snp_decommission *data, int *error)
{
	return sev_do_cmd(SEV_CMD_SNP_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(snp_guest_decommission);

int snp_guest_df_flush(int *error)
{
	return sev_do_cmd(SEV_CMD_SNP_DF_FLUSH, NULL, error);
}
EXPORT_SYMBOL_GPL(snp_guest_df_flush);

int snp_guest_page_reclaim(struct sev_data_snp_page_reclaim *data, int *error)
{
	return sev_do_cmd(SEV_CMD_SNP_PAGE_RECLAIM, data, error);
}
EXPORT_SYMBOL_GPL(snp_guest_page_reclaim);

int snp_guest_dbg_decrypt_page(u64 gctx_pfn, u64 src_pfn, u64 dst_pfn, int *error)
{
	struct sev_data_snp_dbg data = {0};
	struct sev_device *sev;
	int ret;

	if (!psp_master || !psp_master->sev_data)
		return -ENODEV;

	sev = psp_master->sev_data;

	if (!sev->snp_inited)
		return -EINVAL;

	data.gctx_paddr = sme_me_mask | (gctx_pfn << PAGE_SHIFT);
	data.src_addr = sme_me_mask | (src_pfn << PAGE_SHIFT);
	data.dst_addr = sme_me_mask | (dst_pfn << PAGE_SHIFT);
	data.len = PAGE_SIZE;

	/* The destination page must be in the firmware state. */
	if (snp_set_rmp_state(data.dst_addr, 1, true, false, false))
		return -EIO;

	ret = sev_do_cmd(SEV_CMD_SNP_DBG_DECRYPT, &data, error);

	/* Restore the page state */
	if (snp_set_rmp_state(data.dst_addr, 1, false, false, true))
		ret = -EIO;

	return ret;
}
EXPORT_SYMBOL_GPL(snp_guest_dbg_decrypt_page);

int snp_guest_ext_guest_request(struct sev_data_snp_guest_request *data,
				unsigned long vaddr, unsigned long *npages, unsigned long *fw_err)
{
	unsigned long expected_npages;
	struct sev_device *sev;
	int rc;

	if (!psp_master || !psp_master->sev_data)
		return -ENODEV;

	sev = psp_master->sev_data;

	if (!sev->snp_inited)
		return -EINVAL;

	/*
	 * Check if there is enough space to copy the certificate chain. Otherwise
	 * return ERROR code defined in the GHCB specification.
	 */
	expected_npages = sev->snp_certs_len >> PAGE_SHIFT;
	if (*npages < expected_npages) {
		*npages = expected_npages;
		*fw_err = SNP_GUEST_REQ_INVALID_LEN;
		return -EINVAL;
	}

	rc = sev_do_cmd(SEV_CMD_SNP_GUEST_REQUEST, data, (int *)&fw_err);
	if (rc)
		return rc;

	/* Copy the certificate blob */
	if (sev->snp_certs_data) {
		*npages = expected_npages;
		memcpy((void *)vaddr, sev->snp_certs_data, *npages << PAGE_SHIFT);
	} else {
		*npages = 0;
	}

	return rc;
}
EXPORT_SYMBOL_GPL(snp_guest_ext_guest_request);

static void sev_exit(struct kref *ref)
{
	misc_deregister(&misc_dev->misc);
	kfree(misc_dev);
	misc_dev = NULL;
}

static int sev_misc_init(struct sev_device *sev)
{
	struct device *dev = sev->dev;
	int ret;

	/*
	 * SEV feature support can be detected on multiple devices but the SEV
	 * FW commands must be issued on the master. During probe, we do not
	 * know the master hence we create /dev/sev on the first device probe.
	 * sev_do_cmd() finds the right master device to which to issue the
	 * command to the firmware.
	 */
	if (!misc_dev) {
		struct miscdevice *misc;

		misc_dev = kzalloc(sizeof(*misc_dev), GFP_KERNEL);
		if (!misc_dev)
			return -ENOMEM;

		misc = &misc_dev->misc;
		misc->minor = MISC_DYNAMIC_MINOR;
		misc->name = DEVICE_NAME;
		misc->fops = &sev_fops;

		ret = misc_register(misc);
		if (ret)
			return ret;

		kref_init(&misc_dev->refcount);
	} else {
		kref_get(&misc_dev->refcount);
	}

	init_waitqueue_head(&sev->int_queue);
	sev->misc = misc_dev;
	dev_dbg(dev, "registered SEV device\n");

	return 0;
}

int sev_dev_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	struct sev_device *sev;
	int ret = -ENOMEM;

	if (!boot_cpu_has(X86_FEATURE_SEV)) {
		dev_info_once(dev, "SEV: memory encryption not enabled by BIOS\n");
		return 0;
	}

	sev = devm_kzalloc(dev, sizeof(*sev), GFP_KERNEL);
	if (!sev)
		goto e_err;

	sev->cmd_buf = (void *)devm_get_free_pages(dev, GFP_KERNEL, 1);
	if (!sev->cmd_buf)
		goto e_sev;

	sev->cmd_buf_backup = (uint8_t *)sev->cmd_buf + PAGE_SIZE;

	psp->sev_data = sev;

	sev->dev = dev;
	sev->psp = psp;

	sev->io_regs = psp->io_regs;

	sev->vdata = (struct sev_vdata *)psp->vdata->sev;
	if (!sev->vdata) {
		ret = -ENODEV;
		dev_err(dev, "sev: missing driver data\n");
		goto e_buf;
	}

	psp_set_sev_irq_handler(psp, sev_irq_handler, sev);

	ret = sev_misc_init(sev);
	if (ret)
		goto e_irq;

	dev_notice(dev, "sev enabled\n");

	return 0;

e_irq:
	psp_clear_sev_irq_handler(psp);
e_buf:
	devm_free_pages(dev, (unsigned long)sev->cmd_buf);
e_sev:
	devm_kfree(dev, sev);
e_err:
	psp->sev_data = NULL;

	dev_notice(dev, "sev initialization failed\n");

	return ret;
}

static void sev_firmware_shutdown(struct sev_device *sev)
{
	sev_platform_shutdown(NULL);

	if (sev_es_tmr) {
		/* The TMR area was encrypted, flush it from the cache */
		wbinvd_on_all_cpus();

		__snp_free_firmware_pages(virt_to_page(sev_es_tmr),
					  get_order(sev_es_tmr_size),
					  false);
		sev_es_tmr = NULL;
	}

	if (sev_init_ex_buffer) {
		free_pages((unsigned long)sev_init_ex_buffer,
			   get_order(NV_LENGTH));
		sev_init_ex_buffer = NULL;
	}

	if (snp_range_list) {
		free_pages((unsigned long)snp_range_list,
			   get_order(PAGE_SIZE));
		snp_range_list = NULL;
	}

	/*
	 * The host map need to clear the immutable bit so it must be free'd before the
	 * SNP firmware shutdown.
	 */
	free_snp_host_map(sev);

	sev_snp_shutdown(NULL);
}

void sev_dev_destroy(struct psp_device *psp)
{
	struct sev_device *sev = psp->sev_data;

	if (!sev)
		return;

	sev_firmware_shutdown(sev);

	if (sev->misc)
		kref_put(&misc_dev->refcount, sev_exit);

	psp_clear_sev_irq_handler(psp);
}

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return sev_do_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

void sev_pci_init(void)
{
	struct sev_device *sev = psp_master->sev_data;
	int error, rc;

	if (!sev)
		return;

	psp_timeout = psp_probe_timeout;

	if (sev_get_api_version())
		goto err;

	if (sev_version_greater_or_equal(0, 15) &&
	    sev_update_firmware(sev->dev) == 0)
		sev_get_api_version();

	/* If an init_ex_path is provided rely on INIT_EX for PSP initialization
	 * instead of INIT.
	 */
	if (init_ex_path) {
		sev_init_ex_buffer = sev_fw_alloc(NV_LENGTH);
		if (!sev_init_ex_buffer) {
			dev_err(sev->dev,
				"SEV: INIT_EX NV memory allocation failed\n");
			goto err;
		}
	}

	/*
	 * If boot CPU supports the SNP, then first attempt to initialize
	 * the SNP firmware.
	 */
	if (cpu_feature_enabled(X86_FEATURE_SEV_SNP)) {
		if (!sev_version_greater_or_equal(SNP_MIN_API_MAJOR, SNP_MIN_API_MINOR)) {
			dev_err(sev->dev, "SEV-SNP support requires firmware version >= %d:%d\n",
				SNP_MIN_API_MAJOR, SNP_MIN_API_MINOR);
		} else {
			rc = sev_snp_init(&error);
			if (rc) {
				/*
				 * If we failed to INIT SNP then don't abort the probe.
				 * Continue to initialize the legacy SEV firmware.
				 */
				dev_err(sev->dev, "SEV-SNP: failed to INIT error %#x\n", error);
			}
		}

		/*
		 * Allocate the intermediate buffers used for the legacy command handling.
		 */
		if (alloc_snp_host_map(sev)) {
			dev_notice(sev->dev, "Failed to alloc host map (disabling legacy SEV)\n");
			goto skip_legacy;
		}
	}

	/* Obtain the TMR memory area for SEV-ES use */
	sev_es_tmr = sev_fw_alloc(sev_es_tmr_size);
	if (!sev_es_tmr)
		dev_warn(sev->dev,
			 "SEV: TMR allocation failed, SEV-ES support unavailable\n");

	if (!psp_init_on_probe)
		return;

	/* Initialize the platform */
	rc = sev_platform_init(&error);
	if (rc)
		dev_err(sev->dev, "SEV: failed to INIT error %#x, rc %d\n",
			error, rc);

skip_legacy:
	dev_info(sev->dev, "SEV%s API:%d.%d build:%d\n", sev->snp_inited ?
		"-SNP" : "", sev->api_major, sev->api_minor, sev->build);

	return;

err:
	free_snp_host_map(sev);
	psp_master->sev_data = NULL;
}

void sev_pci_exit(void)
{
	struct sev_device *sev = psp_master->sev_data;

	if (!sev)
		return;

	sev_firmware_shutdown(sev);
}
