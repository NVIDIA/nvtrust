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

#ifndef _NSCQ_ATTESTATION_H_
#define _NSCQ_ATTESTATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define NSCQ_API_VERSION(major, minor, patch)                                       \
    (((((uint32_t)major) & 0xFFu) << 24u) | ((((uint32_t)minor) & 0xFFFu) << 12u) | \
     ((((uint32_t)patch) & 0xFFFu) << 0u))
#define NSCQ_API_VERSION_CODE_MAJOR(code) (((code) >> 24u) & 0xFFu)
#define NSCQ_API_VERSION_CODE_MINOR(code) (((code) >> 12u) & 0xFFFu)
#define NSCQ_API_VERSION_CODE_PATCH(code) (((code) >> 0u) & 0xFFFu)

#define NSCQ_API_VERSION_CODE \
    NSCQ_API_VERSION(2, 0, 0)

extern const uint32_t nscq_api_version;

// nscq_rc_t value ranges:
//  0          : success
//  1 to 127   : warnings (success, but with caveats)
//  -128 to -1 : errors
#define NSCQ_RC_SUCCESS                      (0)
#define NSCQ_RC_WARNING_RDT_INIT_FAILURE     (1)
#define NSCQ_RC_ERROR_NOT_IMPLEMENTED        (-1)
#define NSCQ_RC_ERROR_INVALID_UUID           (-2)
#define NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE (-3)
#define NSCQ_RC_ERROR_OVERFLOW               (-4)
#define NSCQ_RC_ERROR_UNEXPECTED_VALUE       (-5)
#define NSCQ_RC_ERROR_UNSUPPORTED_DRV        (-6)
#define NSCQ_RC_ERROR_DRV                    (-7)
#define NSCQ_RC_ERROR_TIMEOUT                (-8)
#define NSCQ_RC_ERROR_EXT                    (-127)
#define NSCQ_RC_ERROR_UNSPECIFIED            (-128)

// The pointer-cast-dereference is done so that these macros can also be used
// with the nscq_*_result_t types, which embed the result code as the first
// member of the result struct.
#ifdef __cplusplus
#define NSCQ_SUCCESS(result) (*(reinterpret_cast<nscq_rc_t*>(&(result))) == NSCQ_RC_SUCCESS)
#define NSCQ_WARNING(result) (*(reinterpret_cast<nscq_rc_t*>(&(result))) > NSCQ_RC_SUCCESS)
#define NSCQ_ERROR(result)   (*(reinterpret_cast<nscq_rc_t*>(&(result))) < NSCQ_RC_SUCCESS)
#else
#define NSCQ_SUCCESS(result) (*((nscq_rc_t*)&(result)) == NSCQ_RC_SUCCESS)
#define NSCQ_WARNING(result) (*((nscq_rc_t*)&(result)) > NSCQ_RC_SUCCESS)
#define NSCQ_ERROR(result)   (*((nscq_rc_t*)&(result)) < NSCQ_RC_SUCCESS)
#endif

#define _NSCQ_RESULT_TYPE(t, m) \
    typedef struct {            \
        nscq_rc_t rc;           \
        t m;                    \
    } nscq_##m##_result_t

typedef int8_t nscq_rc_t;
typedef struct nscq_session_st* nscq_session_t;
typedef struct nscq_observer_st* nscq_observer_t;
typedef struct nscq_writer_st* nscq_writer_t;

// All function callbacks (e.g., used for path observers) are passed using a single type.
// These are cast internally to the appropriate function types internally before use.
typedef void (*nscq_fn_t)(void);

// Convenience macro for casting a function pointer to the common nscq_fn_t type.
#ifdef __cplusplus
#define NSCQ_FN(fn) reinterpret_cast<nscq_fn_t>(fn)
#else
#define NSCQ_FN(fn) ((nscq_fn_t)&fn)
#endif

typedef struct {
    uint8_t bytes[16];
} nscq_uuid_t;

#define NSCQ_ARCH_SV10  (0)
#define NSCQ_ARCH_LR10  (1)
#define NSCQ_ARCH_LS10  (2)

typedef int8_t nscq_arch_t;

typedef struct {
    char data[64];
} nscq_label_t;

#define NSCQ_DEVICE_TNVL_MODE_UNKNOWN   (-1)
#define NSCQ_DEVICE_TNVL_MODE_DISABLED (0)
#define NSCQ_DEVICE_TNVL_MODE_ENABLED  (1)
#define NSCQ_DEVICE_TNVL_MODE_FAILURE  (2)
#define NSCQ_DEVICE_TNVL_MODE_LOCKED   (3)

typedef int8_t nscq_tnvl_status_t;

#define NSCQ_ATTESTATION_REPORT_NONCE_SIZE 0x20
#define NSCQ_ATTESTATION_REPORT_SIZE 0x2000

typedef struct
{
  uint32_t report_size;
  uint8_t report[NSCQ_ATTESTATION_REPORT_SIZE];
} nscq_attestation_report_t;

#define NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE 0x1400

typedef struct
{
    uint8_t cert_chain[NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE];
    uint32_t cert_chain_size;
} nscq_attestation_certificate_t;

_NSCQ_RESULT_TYPE(nscq_session_t, session);
_NSCQ_RESULT_TYPE(nscq_observer_t, observer);
_NSCQ_RESULT_TYPE(nscq_writer_t, writer);

nscq_rc_t nscq_uuid_to_label(const nscq_uuid_t*, nscq_label_t*, uint32_t);

#define NSCQ_SESSION_CREATE_MOUNT_DEVICES (0x1u)

nscq_session_result_t nscq_session_create(uint32_t);
void nscq_session_destroy(nscq_session_t);

nscq_rc_t nscq_session_path_observe(nscq_session_t, const char*, nscq_fn_t, void*, uint32_t);

nscq_rc_t nscq_session_set_input(nscq_session_t, uint32_t, void*, uint32_t);

#ifdef __cplusplus
}
#endif

#endif // _NSCQ_ATTESTATION_H_
