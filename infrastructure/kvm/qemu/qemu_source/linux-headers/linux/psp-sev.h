/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Userspace interface for AMD Secure Encrypted Virtualization (SEV)
 * platform management commands.
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API specification is available at: https://developer.amd.com/sev/
 */

#ifndef __PSP_SEV_USER_H__
#define __PSP_SEV_USER_H__

#include <linux/types.h>

/**
 * SEV platform commands
 */
enum {
	SEV_FACTORY_RESET = 0,
	SEV_PLATFORM_STATUS,
	SEV_PEK_GEN,
	SEV_PEK_CSR,
	SEV_PDH_GEN,
	SEV_PDH_CERT_EXPORT,
	SEV_PEK_CERT_IMPORT,
	SEV_GET_ID,	/* This command is deprecated, use SEV_GET_ID2 */
	SEV_GET_ID2,
	SNP_PLATFORM_STATUS,
	SNP_SET_EXT_CONFIG,
	SNP_GET_EXT_CONFIG,

	SEV_MAX,
};

/**
 * SEV Firmware status code
 */
typedef enum {
	SEV_RET_SUCCESS = 0,
	SEV_RET_INVALID_PLATFORM_STATE,
	SEV_RET_INVALID_GUEST_STATE,
	SEV_RET_INAVLID_CONFIG,
	SEV_RET_INVALID_LEN,
	SEV_RET_ALREADY_OWNED,
	SEV_RET_INVALID_CERTIFICATE,
	SEV_RET_POLICY_FAILURE,
	SEV_RET_INACTIVE,
	SEV_RET_INVALID_ADDRESS,
	SEV_RET_BAD_SIGNATURE,
	SEV_RET_BAD_MEASUREMENT,
	SEV_RET_ASID_OWNED,
	SEV_RET_INVALID_ASID,
	SEV_RET_WBINVD_REQUIRED,
	SEV_RET_DFFLUSH_REQUIRED,
	SEV_RET_INVALID_GUEST,
	SEV_RET_INVALID_COMMAND,
	SEV_RET_ACTIVE,
	SEV_RET_HWSEV_RET_PLATFORM,
	SEV_RET_HWSEV_RET_UNSAFE,
	SEV_RET_UNSUPPORTED,
	SEV_RET_INVALID_PARAM,
	SEV_RET_RESOURCE_LIMIT,
	SEV_RET_SECURE_DATA_INVALID,
	SEV_RET_INVALID_PAGE_SIZE,
	SEV_RET_INVALID_PAGE_STATE,
	SEV_RET_INVALID_MDATA_ENTRY,
	SEV_RET_INVALID_PAGE_OWNER,
	SEV_RET_AEAD_OFLOW,
	SEV_RET_RMP_INIT_REQUIRED,
	SEV_RET_MAX,
} sev_ret_code;

/**
 * struct sev_user_data_status - PLATFORM_STATUS command parameters
 *
 * @major: major API version
 * @minor: minor API version
 * @state: platform state
 * @flags: platform config flags
 * @build: firmware build id for API version
 * @guest_count: number of active guests
 */
struct sev_user_data_status {
	__u8 api_major;				/* Out */
	__u8 api_minor;				/* Out */
	__u8 state;				/* Out */
	__u32 flags;				/* Out */
	__u8 build;				/* Out */
	__u32 guest_count;			/* Out */
} __attribute__((packed));

#define SEV_STATUS_FLAGS_CONFIG_ES	0x0100

/**
 * struct sev_user_data_pek_csr - PEK_CSR command parameters
 *
 * @address: PEK certificate chain
 * @length: length of certificate
 */
struct sev_user_data_pek_csr {
	__u64 address;				/* In */
	__u32 length;				/* In/Out */
} __attribute__((packed));

/**
 * struct sev_user_data_cert_import - PEK_CERT_IMPORT command parameters
 *
 * @pek_address: PEK certificate chain
 * @pek_len: length of PEK certificate
 * @oca_address: OCA certificate chain
 * @oca_len: length of OCA certificate
 */
struct sev_user_data_pek_cert_import {
	__u64 pek_cert_address;			/* In */
	__u32 pek_cert_len;			/* In */
	__u64 oca_cert_address;			/* In */
	__u32 oca_cert_len;			/* In */
} __attribute__((packed));

/**
 * struct sev_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_len: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_len: length of PDH certificate chain
 */
struct sev_user_data_pdh_cert_export {
	__u64 pdh_cert_address;			/* In */
	__u32 pdh_cert_len;			/* In/Out */
	__u64 cert_chain_address;		/* In */
	__u32 cert_chain_len;			/* In/Out */
} __attribute__((packed));

/**
 * struct sev_user_data_get_id - GET_ID command parameters (deprecated)
 *
 * @socket1: Buffer to pass unique ID of first socket
 * @socket2: Buffer to pass unique ID of second socket
 */
struct sev_user_data_get_id {
	__u8 socket1[64];			/* Out */
	__u8 socket2[64];			/* Out */
} __attribute__((packed));

/**
 * struct sev_user_data_get_id2 - GET_ID command parameters
 * @address: Buffer to store unique ID
 * @length: length of the unique ID
 */
struct sev_user_data_get_id2 {
	__u64 address;				/* In */
	__u32 length;				/* In/Out */
} __attribute__((packed));

/**
 * struct sev_user_data_snp_status - SNP status
 *
 * @major: API major version
 * @minor: API minor version
 * @state: current platform state
 * @build: firmware build id for the API version
 * @guest_count: the number of guest currently managed by the firmware
 * @tcb_version: current TCB version
 */
struct sev_user_data_snp_status {
	__u8 api_major;		/* Out */
	__u8 api_minor;		/* Out */
	__u8 state;		/* Out */
	__u8 rsvd;
	__u32 build_id;		/* Out */
	__u32 rsvd1;
	__u32 guest_count;	/* Out */
	__u64 tcb_version;	/* Out */
	__u64 rsvd2;
} __attribute__((packed));

/*
 * struct sev_user_data_snp_config - system wide configuration value for SNP.
 *
 * @reported_tcb: The TCB version to report in the guest attestation report.
 * @mask_chip_id: Indicates that the CHID_ID field in the attestation report
 * will always be zero.
 */
struct sev_user_data_snp_config {
	__u64 reported_tcb;     /* In */
	__u32 mask_chip_id;     /* In */
	__u8 rsvd[52];
} __attribute__((packed));

/**
 * struct sev_data_snp_ext_config - system wide configuration value for SNP.
 *
 * @config_address: address of the struct sev_user_data_snp_config or 0 when
 *		reported_tcb does not need to be updated.
 * @certs_address: address of extended guest request certificate chain or
 *              0 when previous certificate should be removed on SNP_SET_EXT_CONFIG.
 * @certs_len: length of the certs
 */
struct sev_user_data_ext_snp_config {
	__u64 config_address;		/* In */
	__u64 certs_address;		/* In */
	__u32 certs_len;		/* In */
};

/**
 * struct sev_issue_cmd - SEV ioctl parameters
 *
 * @cmd: SEV commands to execute
 * @opaque: pointer to the command structure
 * @error: SEV FW return code on failure
 */
struct sev_issue_cmd {
	__u32 cmd;				/* In */
	__u64 data;				/* In */
	__u32 error;				/* Out */
} __attribute__((packed));

#define SEV_IOC_TYPE		'S'
#define SEV_ISSUE_CMD	_IOWR(SEV_IOC_TYPE, 0x0, struct sev_issue_cmd)

#endif /* __PSP_USER_SEV_H */
