from ..utils.cert_chain_utils import get_switch_cert_chain


class NVSwitch:

    def __init__(self, uuid, attestation_cert_chain, attestation_report):
        self.uuid = uuid
        self.attestation_cert_chain = get_switch_cert_chain(attestation_cert_chain)
        self.attestation_report = attestation_report
