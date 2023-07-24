/*
 * QEMU SEV stub
 *
 * Copyright Advanced Micro Devices 2018
 *
 * Authors:
 *      Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "sev_i386.h"

SevInfo *sev_get_info(void)
{
    return NULL;
}

bool sev_enabled(void)
{
    return false;
}

uint64_t sev_get_me_mask(void)
{
    return ~0;
}

uint32_t sev_get_cbit_position(void)
{
    return 0;
}

uint32_t sev_get_reduced_phys_bits(void)
{
    return 0;
}

char *sev_get_launch_measurement(void)
{
    return NULL;
}

SevCapability *sev_get_capabilities(Error **errp)
{
    error_setg(errp, "SEV is not available in this QEMU");
    return NULL;
}

int sev_inject_launch_secret(const char *hdr, const char *secret,
                             uint64_t gpa, Error **errp)
{
    return 1;
}

int sev_encrypt_flash(hwaddr gpa, uint8_t *ptr, uint64_t len, Error **errp)
{
    return 0;
}

bool sev_es_enabled(void)
{
    return false;
}

void sev_es_set_reset_vector(CPUState *cpu)
{
}

int sev_es_save_reset_vector(void *flash_ptr, uint64_t flash_size)
{
    abort();
}

SevAttestationReport *
sev_get_attestation_report(const char *mnonce, Error **errp)
{
    error_setg(errp, "SEV is not available in this QEMU");
    return NULL;
}

bool sev_add_kernel_loader_hashes(SevKernelLoaderContext *ctx, Error **errp)
{
    g_assert_not_reached();
}

bool
sev_snp_enabled(void)
{
    return false;
}
