"""Node authentication (item 17).

TS 29.244 defines no PFCP-level authentication; N4 is protected at the
transport layer (IPsec/NDS-IP per TS 33.210/33.501) and peers are
identified by Node ID.  This module therefore simulates the two
observable parts:

* ``NodeAuthenticator`` - allow-list of trusted Node IDs (IP or FQDN);
  an untrusted peer's Association Setup is rejected (cause 64).
* ``IpsecProtector``   - wraps PFCP packets in ESP transport mode so the
  generated PCAP shows a protected N4 interface.
"""
import os

from .ies import CAUSE_ACCEPTED, CAUSE_REJECTED


class NodeAuthenticator:
    def __init__(self, trusted=()):
        self.trusted = {t.lower() for t in trusted}
        self.associated = set()

    def authenticate(self, *identities):
        """True if no allow-list is set or any identity (FQDN / address)
        of the peer is trusted."""
        return not self.trusted or any(i.lower() in self.trusted
                                       for i in identities)

    def association_cause(self, *identities):
        if self.authenticate(*identities):
            self.associated.update(i.lower() for i in identities)
            return CAUSE_ACCEPTED
        return CAUSE_REJECTED

    def is_associated(self, *identities):
        return any(i.lower() in self.associated for i in identities)

    def drop(self, *identities):
        for i in identities:
            self.associated.discard(i.lower())


class IpsecProtector:
    """ESP (AES-CBC + HMAC-SHA1-96) transport-mode protection of N4."""

    def __init__(self, spi=0x1001, key=None, auth_key=None):
        from scapy.layers.ipsec import SecurityAssociation, ESP
        self.key = key or os.urandom(16)
        self.auth_key = auth_key or os.urandom(20)
        self.sa = SecurityAssociation(
            ESP, spi=spi, crypt_algo="AES-CBC", crypt_key=self.key,
            auth_algo="HMAC-SHA1-96", auth_key=self.auth_key)

    def protect(self, pkt):
        t = pkt.time
        out = self.sa.encrypt(pkt)
        out.time = t
        return out
