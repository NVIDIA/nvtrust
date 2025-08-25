//
// Copyright 2020-2025 NVIDIA Corporation.  All rights reserved.
//
// NOTICE TO USER:
//
// This source code is subject to NVIDIA ownership rights under U.S. and
// international Copyright laws.  Users and possessors of this source code
// are hereby granted a nonexclusive, royalty-free license to use this code
// in individual and commercial software.
//
// NVIDIA MAKES NO REPRESENTATION ABOUT THE SUITABILITY OF THIS SOURCE
// CODE FOR ANY PURPOSE.  IT IS PROVIDED "AS IS" WITHOUT EXPRESS OR
// IMPLIED WARRANTY OF ANY KIND.  NVIDIA DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOURCE CODE, INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE.
// IN NO EVENT SHALL NVIDIA BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL,
// OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
// OF USE, DATA OR PROFITS,  WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
// OR OTHER TORTIOUS ACTION,  ARISING OUT OF OR IN CONNECTION WITH THE USE
// OR PERFORMANCE OF THIS SOURCE CODE.
//
// U.S. Government End Users.   This source code is a "commercial item" as
// that term is defined at  48 C.F.R. 2.101 (OCT 1995), consisting  of
// "commercial computer  software"  and "commercial computer software
// documentation" as such terms are  used in 48 C.F.R. 12.212 (SEPT 1995)
// and is provided to the U.S. Government only as a commercial end item.
// Consistent with 48 C.F.R.12.212 and 48 C.F.R. 227.7202-1 through
// 227.7202-4 (JUNE 1995), all U.S. Government End Users acquire the
// source code with only those rights set forth herein.
//
// Any use of this source code in individual and commercial software must
// include, in the user documentation and internal comments to the code,
// the above Disclaimer and U.S. Government End Users Notice.
//

#ifndef _NSCQ_ATTESTATION_PATH_H_
#define _NSCQ_ATTESTATION_PATH_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define NSCQ_PATH(p) static_cast<const char*>(nscq_##p)
#else
#define NSCQ_PATH(p) nscq_##p
#endif

#define _NSCQ_DEF_PATH(name, path) static const char name[] = path

_NSCQ_DEF_PATH(nscq_nvswitch_drv_version, "/drv/nvswitch/version");
_NSCQ_DEF_PATH(nscq_nvswitch_device_uuid_path, "/drv/nvswitch/{device}/uuid");
_NSCQ_DEF_PATH(nscq_nvswitch_arch, "/{nvswitch}/id/arch");
_NSCQ_DEF_PATH(nscq_nvswitch_pcie_mode, "/{nvswitch}/config/pcie_mode");
_NSCQ_DEF_PATH(nscq_nvswitch_attestation_report, "/{nvswitch}/config/attestation_report");
_NSCQ_DEF_PATH(nscq_nvswitch_certificate, "/{nvswitch}/config/certificate");
#undef _NSCQ_DEF_PATH

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _NSCQ_ATTESTATION_PATH_H_
