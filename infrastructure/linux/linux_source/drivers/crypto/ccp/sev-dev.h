/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Platform Security Processor (PSP) interface driver
 *
 * Copyright (C) 2017-2019 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __SEV_DEV_H__
#define __SEV_DEV_H__

#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/dmapool.h>
#include <linux/hw_random.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/dmaengine.h>
#include <linux/psp-sev.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>

#define SEV_CMD_COMPLETE		BIT(1)
#define SEV_CMDRESP_CMD_SHIFT		16
#define SEV_CMDRESP_IOC			BIT(0)

#define MAX_SNP_HOST_MAP_BUFS		2

struct sev_misc_dev {
	struct kref refcount;
	struct miscdevice misc;
};

struct snp_host_map {
	u64 paddr;
	u32 len;
	void *host;
	bool active;
};

struct sev_device {
	struct device *dev;
	struct psp_device *psp;

	void __iomem *io_regs;

	struct sev_vdata *vdata;

	int state;
	unsigned int int_rcvd;
	wait_queue_head_t int_queue;
	struct sev_misc_dev *misc;

	u8 api_major;
	u8 api_minor;
	u8 build;

	void *cmd_buf;
	void *cmd_buf_backup;
	int cmd_buf_active;

	bool snp_inited;
	struct snp_host_map snp_host_map[MAX_SNP_HOST_MAP_BUFS];
	void *snp_certs_data;
	u32 snp_certs_len;
	struct sev_user_data_snp_config snp_config;
};

int sev_dev_init(struct psp_device *psp);
void sev_dev_destroy(struct psp_device *psp);

void sev_pci_init(void);
void sev_pci_exit(void);

#endif /* __SEV_DEV_H */
