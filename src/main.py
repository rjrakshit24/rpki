#!/usr/bin/env python3
import logging
import coloredlogs
import psutil
import traceback
import json
import sys
import os
from mrtparse import *
from asn1crypto.core import *
from asn1crypto.cms import ContentInfo, ContentType, EncapsulatedContentInfo
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
import radix

class ASID(Integer):
    pass

class AddrBits(BitString):
    pass

class Addr(Sequence):
    _fields = [
        ("address", AddrBits),
        ("maxLength", Integer, {"optional": True})
    ]

class AddrSet(SequenceOf):
    _child_spec = Addr

class AddrFamily(Sequence):
    _fields = [
        ("addressFamily", OctetString),
        ("addresses", AddrSet)
    ]

class AddrSeq(SequenceOf):
    _child_spec = AddrFamily

class ROA(Sequence):
    _fields = [
        ("version", Integer, {"implicit": 0, "default": 0}),
        ("asID", ASID),
        ("ipAddrBlocks", AddrSeq)
    ]

ContentType._map["1.2.840.113549.1.9.16.1.24"] = "routeOriginAuthz"
EncapsulatedContentInfo._oid_specs["routeOriginAuthz"] = ROA

class Result:
    roas = radix.Radix()
    total_valid = 0
    total_messages = 0
    total_invalid = 0
    total_unknown = 0
    total_unsafe = None

    @classmethod
    def toString(cls) -> str:
        return json.dumps(dict(total_messages=cls.total_messages,total_invalid=cls.total_invalid,total_unknown=cls.total_unknown,total_unsafe=cls.total_unsafe))

class BGPMessage:
    def __init__(self, bgpmessage, index):
        self.type = "valid"
        self.tv_sec = list(bgpmessage.get('timestamp').keys())[0]
        self.tv_usec = bgpmessage.get('microsecond_timestamp')
        self.peer_ip = bgpmessage.get('peer_ip')
        self.peer_asn = int(bgpmessage.get('peer_as'))
        self.prefix = f"{bgpmessage['bgp_message']['nlri'][index]['prefix']}/{bgpmessage['bgp_message']['nlri'][index]['prefix_length']}"
        self._prefix_length=bgpmessage['bgp_message']['nlri'][index]['prefix_length']
        self.as_path = list()
        for x in bgpmessage['bgp_message']['path_attributes']:
            if x['type'].get(2):
                for y in x['value']:
                    if y['type'].get(2):
                        self.as_path.append({"type": "sequence", "asns": [int(z) for z in y['value']]})
                    elif y['type'].get(1):
                        self.as_path.append({"type": "set", "asns": [int(z) for z in y['value']]})
                    else:
                        pass

    def __str__(self) -> str:
        t = self.__dict__.copy()
        t.pop('_prefix_length')
        return json.dumps(t)

def ipv4_prefix_from_bits(xs):
    address = 0
    for x in xs:
        address = (address << 1) | x
    if len(xs) < 32:
        address <<= 32 - len(xs)
    return IPv4Address(address), len(xs)

def ipv6_prefix_from_bits(xs):
    address = 0
    for x in xs:
        address = (address << 1) | x
    if len(xs) < 128:
        address <<= 128 - len(xs)
    return IPv6Address(address), len(xs)
    
def loadROA(p: Path) -> list:
    prefixes = list()
    cms = ContentInfo.load(p.read_bytes()).native
    if cms["content"]["encap_content_info"]["content_type"] == "routeOriginAuthz":
        roa = cms["content"]["encap_content_info"]["content"]
        for block in roa["ipAddrBlocks"]:
            family = int.from_bytes(block["addressFamily"], byteorder="big")
            if family == 1:
                for addr in block["addresses"]:
                    prefix, prefix_length = ipv4_prefix_from_bits(addr["address"])
                    max_length = addr["maxLength"] or prefix_length
                    prefix = f"{prefix}/{prefix_length}"
                    prefixes.append((prefix, max_length, roa["asID"]))
            elif family == 2:
                for addr in block["addresses"]:
                    prefix, prefix_length = ipv6_prefix_from_bits(addr["address"])
                    max_length = addr["maxLength"] or prefix_length
                    prefix = f"{prefix}/{prefix_length}"
                    prefixes.append((prefix, max_length, roa["asID"]))
            else:
                raise Exception(f"unknown address family: {family}")
    return prefixes

def parseMRT(p: Path):
    logging.info(f"Begin Parsing MRT File: {str(p)}")

    for entry in Reader(str(p)):
        Result.total_messages += 1
        if entry.data['bgp_message']['type'].get(2,False):
            if len(entry.data['bgp_message']['nlri'])>0:
                for i in range(len(entry.data['bgp_message']['nlri'])):
                    bgpMessage = BGPMessage(entry.data,i)
                    candidateROAS = Result.roas.search_covering(bgpMessage.prefix)
                    if len(candidateROAS)>0:
                        for path in bgpMessage.as_path:
                            if path.get('type') == 'sequence':
                                originAS = path.get('asns')[-1]
                                flag = False
                                if originAS != 0:
                                    for candidateROA in candidateROAS:
                                        if candidateROA.data.get(originAS):
                                            if bgpMessage._prefix_length <= candidateROA.data.get(originAS):
                                                flag = True
                                                Result.total_valid += 1
                                                break
                                if not flag:
                                    logging.debug("Origin AS Not Found")
                                    bgpMessage.type = "invalid"
                                    Result.total_invalid += 1
                                    print(bgpMessage)
                    else:
                        logging.debug("No Candidate ROAS Found")
                        bgpMessage.type = "unknown"
                        Result.total_unknown += 1
                        print(bgpMessage)
            else:
                logging.debug("NLRI Empty")
                logging.debug(entry.data)
        else:
            logging.debug("BGPMessage Type Mismatch")
            logging.debug(entry.data)

    logging.info(f"End Parsing MRT File: {str(p)}")

def main():
    # coloredlogs.install('INFO')
    rpki_root = sys.argv[1]
    # rpki_root = "/Users/rjrakshit24/Desktop/NEU/Network Security/Assignment 04/rpki_cache"
    mrt_root = sys.argv[2]
    # mrt_root = "/Users/rjrakshit24/Desktop/NEU/Network Security/Assignment 04/mrt_data test"

    logging.info(f"loading ROAs from {rpki_root}")
    for root, dirs, files in os.walk(rpki_root):
        for f in files:
            p = Path(root) / f
            if not p.name.endswith("roa"):
                continue
            try:
                addresses=loadROA(p)
                for cidr, maxLen, asn in addresses:
                    rnode = Result.roas.add(str(cidr))
                    if rnode.data.get(asn):
                        rnode.data[asn]=max(rnode.data.get(asn),maxLen)
                    else:
                        rnode.data[asn]=maxLen    
            except:
                # logging.error(f"Error ROA at {p}")
                # traceback.print_exc()
                continue
                
    counter=0
    for r in Result.roas.nodes():
        counter+=1
    logging.info(f"Nodes in Radix Tree: {counter}")

    logging.info(f"loading MRTs from {mrt_root}")
    for root, dirs, files in os.walk(mrt_root):
        for f in files:
            p = Path(root) / f
            if not p.name.endswith('bz2'):
                continue
            try:
                parseMRT(p)
            except:
                # logging.error(f"Error in {p}")
                # traceback.print_exc()
                continue
    print(Result.toString())

if __name__ == "__main__":
    main()