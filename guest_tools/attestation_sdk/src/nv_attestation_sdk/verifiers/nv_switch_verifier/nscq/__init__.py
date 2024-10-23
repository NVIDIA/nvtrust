#
# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

from collections import defaultdict
import ctypes

from .paths import (
    nscq_nvswitch_device_uuid_path, nscq_nvswitch_arch
)
from .pynscq import (
    nscq_uuid_to_label,
    p_nscq_uuid_t,
    nscq_rc_t,
    NSCQSession,
    user_data_type,
    nscq_tnvl_status_t,
    nscq_attestation_certificate_t,
    nscq_attestation_report_t,
    nscqCallback, nscq_arch_t,
)

class NSCQHandler:
    
    EXPECTED_NONCE_LENGTH              = 32
    TNVL_STATUS_PATH                   = b"/config/pcie_mode"
    UUID_PATH                          = nscq_nvswitch_device_uuid_path
    ARCH_PATH                          = nscq_nvswitch_arch
    ATTESTATION_CERTIFICATE_CHAIN_PATH = b"/config/certificate"
    ATTESTATION_REPORT_PATH            = b"/config/attestation_report"
    TNVL_BIT_POSITION                  = 0
    LOCK_BIT_POSITION                  = 1

    def dictionary_init(self):
        return "NOT PRESENT"

    uuid               = []
    tnvl_status        = defaultdict(dictionary_init)
    certificate_chain  = defaultdict(dictionary_init)
    attestation_report = defaultdict(dictionary_init)
    nscq_session       = None
    return_code        = None
    arch               = None

    def __init__(self):
        """ The constructor for the NSCQHandler class.
        """
        self.nscq_session = NSCQSession(flags=1)

    def _build_path(self, device):
        if device is None:
            return b"/{nvswitch}"
        return b"/" + device.encode("UTF-8")

    @nscqCallback(p_nscq_uuid_t, nscq_rc_t, p_nscq_uuid_t, user_data_type)
    def _device_uuid_callback(device, rc, uuid, _user_data):
        label = nscq_uuid_to_label(uuid.contents)
        NSCQHandler.uuid.append(label.data.decode("UTF-8"))
        NSCQHandler.return_code = rc.value

    @nscqCallback(p_nscq_uuid_t, nscq_rc_t, nscq_arch_t, user_data_type)
    def _device_architecture_callback(device, rc, arch, _user_data):
        label = nscq_uuid_to_label(device.contents)
        NSCQHandler.arch = arch.value
        NSCQHandler.return_code = rc.value

    @nscqCallback(p_nscq_uuid_t, nscq_rc_t, nscq_tnvl_status_t, user_data_type)
    def _device_tnvl_status_callback(device, rc, tnvl, _user_data):
        label = nscq_uuid_to_label(device.contents)
        NSCQHandler.tnvl_status[label.data.decode("UTF-8")] = tnvl.value
        NSCQHandler.return_code = rc.value

    @nscqCallback(p_nscq_uuid_t, nscq_rc_t, nscq_attestation_certificate_t, user_data_type)
    def _device_attestation_certificate_callback(device, rc, cert, _user_data):
        label = nscq_uuid_to_label(device.contents)
        NSCQHandler.certificate_chain[label.data.decode("UTF-8")] = bytes(list(cert.cert_chain)[:cert.cert_chain_size])
        NSCQHandler.return_code = rc.value

    @nscqCallback(p_nscq_uuid_t, nscq_rc_t, nscq_attestation_report_t, user_data_type)
    def _device_attestation_report_callback(device, rc, report, _user_data):
        label = nscq_uuid_to_label(device.contents)
        NSCQHandler.attestation_report[label.data.decode("UTF-8")] = bytes(list(report.report)[:report.report_size])
        NSCQHandler.return_code = rc.value

    def get_all_switch_uuid(self):
        """ A function to fetch the UUIDs of all the switches.

        Returns:
            tuple (list, int): tuple containing the list of all switches UUIDs and the return code.
        """
        NSCQHandler.uuid = []
        self.nscq_session.path_observe(NSCQHandler.UUID_PATH,
                                       NSCQHandler._device_uuid_callback)
        return (self.uuid, NSCQHandler.return_code)

    def get_switch_architecture(self):
        """ A function to fetch architecture of the switch
        """
        self.nscq_session.path_observe(NSCQHandler.ARCH_PATH,
                                       NSCQHandler._device_architecture_callback)
        return (self.arch, NSCQHandler.return_code)

    def get_switch_tnvl_status(self, device):
        """ A function to fetch the TNVL mode info of the switch.

        Args:
            device (str): the UUID of the switch.

        Returns:
            tuple (int, int): tuple containing the tnvl mode info and the return code.
                              In case of invalid arguments, returns tuple containing 
                              None for the tnvl mode info and return the code.
        """
        if not isinstance(device, str):
            return (None, None)

        self.nscq_session.path_observe(self._build_path(device) + NSCQHandler.TNVL_STATUS_PATH,
                                        NSCQHandler._device_tnvl_status_callback)
        return (self.tnvl_status[device], NSCQHandler.return_code)

    def get_all_switch_tnvl_status(self):
        """ A function the fetch the TNVL mode info of all the switches. 

        Returns:
            tuple (collections.defaultdict, int): tuple containing the dictionary 
                                                  of all the switchs TNVL mode and the return code.
        """
        self.nscq_session.path_observe(self._build_path(None) + NSCQHandler.TNVL_STATUS_PATH,
                                       NSCQHandler._device_tnvl_status_callback)
        return (self.tnvl_status, NSCQHandler.return_code)
    
    def is_switch_tnvl_mode(self, device):
        """ A function to check the if the swtich is in TNVL mode or not.

        Args:
            device (str): the UUID of the switch.

        Returns:
            tuple (bool, int): tuple containing True or False if the TNVL mode is set or not respectively
                               and the return code.In case of invalid arguments, returns tuple containing 
                                None for the tnvl mode and return the code.
        """
        if not isinstance(device, str):
            return (None, None)

        value, return_code = self.get_switch_tnvl_status(device)
        return (((value>>NSCQHandler.TNVL_BIT_POSITION & 1) == 1), return_code)
    

    def is_switch_lock_mode(self, device):
        """ A function to check the if the swtich is in lock mode or not.

        Args:
            device (str): the UUID of the switch.

        Returns:
            tuple (bool, int): tuple containing True or False if the Lock mode is set or not respectively
                               and the return code. In case of invalid arguments, returns tuple containing 
                                None for the lock mode and return the code.
        """
        if not isinstance(device, str):
            return (None, None)

        value, return_code = self.get_switch_tnvl_status(device)
        return (((value>>NSCQHandler.LOCK_BIT_POSITION & 1) == 1), return_code)
        

    def get_switch_attestation_certificate_chain(self, device):
        """ A function to fetch the switch attestation certificate chains of switch.

        Args:
            device (str): the UUID of the switch.

        Returns:
            tuple (bytes, int): A tuple containing the switch attestation certificate chain 
                                and the return code as int.
                                In case of invalid arguments, returns tuple containing 
                                None for the certificate chain and return the code.
        """
        if not isinstance(device,str):
            return (None, None)
        
        self.nscq_session.path_observe(self._build_path(device) + NSCQHandler.ATTESTATION_CERTIFICATE_CHAIN_PATH,
                                    NSCQHandler._device_attestation_certificate_callback)
        return (self.certificate_chain[device], NSCQHandler.return_code)

    def get_all_switch_attestation_certificate_chain(self):
        """ A function to fetch the switch attestation certificate chains of all the switches.

        Returns:
            tuple (collections.defaultdict, int): A tuple containing all switch attestation certificate chain 
                                                  as a dictionary and the return code as int.
                                                  In case of invalid arguments, returns tuple containing 
                                                  None for the certificate chain and return the code.
        """
        self.nscq_session.path_observe(self._build_path(None) + NSCQHandler.ATTESTATION_CERTIFICATE_CHAIN_PATH,
                                       NSCQHandler._device_attestation_certificate_callback)
        return (self.certificate_chain, NSCQHandler.return_code)

    def get_switch_attestation_report(self, device, nonce):
        """ A method to fetch the attestation report from the switch.

        Args:
            device (str): the UUID of the switch
            nonce (bytes): the 32 byte long nonce

        Returns:
            tuple (bytes, int): the attestation report and the return code respectively.
                                In case of invalid arguments, returns tuple containing 
                                None for the attestation report and return the code.
        """
        if len(nonce) != NSCQHandler.EXPECTED_NONCE_LENGTH or not isinstance(device, str):
            return (None, None)

        nonce_p = [x for x in nonce]
        nonce_ctype = (ctypes.c_uint8 * len(nonce_p))(*nonce_p)
        self.nscq_session.set_input(nonce_ctype, len(nonce_ctype))
        self.nscq_session.path_observe(self._build_path(device) + NSCQHandler.ATTESTATION_REPORT_PATH,
                                       NSCQHandler._device_attestation_report_callback)
        return (self.attestation_report[device], NSCQHandler.return_code)

    def get_all_switch_attestation_report(self, nonce):
        """ A method to fetch the attestation report from all the switches.

        Args:
            nonce (bytes): the 32 byte long nonce

        Returns:
            tuple (collections.defaultdict, int) : A tuple containing all switch attestation report 
                                                   as a dictionary and the return code as int.
                                                   In case of invalid arguments, returns tuple containing 
                                                   None for the report and return the code.
        """

        if len(nonce) != NSCQHandler.EXPECTED_NONCE_LENGTH:
            return (None, None)

        nonce_p = [x for x in nonce]
        nonce_ctype = (ctypes.c_uint8 * len(nonce_p))(*nonce_p)
        self.nscq_session.set_input(nonce_ctype, len(nonce_ctype))
        self.nscq_session.path_observe(self._build_path(None) + NSCQHandler.ATTESTATION_REPORT_PATH,
                                       NSCQHandler._device_attestation_report_callback)
        return (self.attestation_report, NSCQHandler.return_code)
