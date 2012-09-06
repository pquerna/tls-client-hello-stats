#!/usr/bin/env python

# Copyright 2012 Paul Querna
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import os
import sys

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'third_party', 'dpkt')
if p not in sys.path:
    sys.path.insert(0, p)

import dpkt

def pcap_reader(fp):
    return dpkt.pcap.Reader(fp)

def as_percent(a, b):
    if a == 0:
        return "0%"
    if a > b:
        assert('invalid percentage')

    val = float(a) / float(b)
    return "%.2f%%" % (val * 100)

TLS_HANDSHAKE = 22

def gather_statistics(cap):
    counters = {
        'client_hellos_total': 0,
        'SSLv3_clients': 0,
        'TLSv1_clients': 0,
        'TLSv1.1_clients': 0,
        'TLSv1.2_clients': 0,
        'session_ticket_support': 0,
        'session_id_sent': 0,
        'deflate_support': 0,
    }
    pkt_count = 0
    for ts, buf in cap:
        pkt_count += 1
        eth = dpkt.ethernet.Ethernet(buf)
        #print 'pkt: %d' % (pkt_count)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # TODO: consider doing TCP streams, so multi-packet things can be parsed right... "meh"
        tcp = ip.data
        if tcp.dport != 443 and tcp.sport != 443:
            continue

        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        if ord(tcp.data[0]) != TLS_HANDSHAKE:
            continue

        #print 'tcp.sport: %d' % (tcp.sport)
        #print 'tcp.dport: %d' % (tcp.dport)
        #print 'tcp.data[0]: %d' % ord(tcp.data[0])
        #print 'tcp.sum: 0x%x' % tcp.sum

        records = []
        try:
            records, bytes_used = dpkt.ssl.TLSMultiFactory(tcp.data)
        except dpkt.ssl.SSL3Exception, e:
            # TODO: debug these
            continue
        except dpkt.dpkt.NeedData, e:
            # TODO: meeeeh
            continue

        if len(records) <= 0:
            continue

        for record in records:
            # TLS handshake only
            if record.type != 22:
                continue
            if len(record.data) == 0:
                continue
            # Client Hello only
            if ord(record.data[0]) != 1:
                continue

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData, e:
                # TODO: shouldn't happen in practice for handshakes... but could. meh.
                continue

            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                continue

            counters['client_hellos_total'] += 1

            ch = handshake.data

            if ch.version == dpkt.ssl.SSL3_V:
                counters['SSLv3_clients'] += 1
            elif ch.version == dpkt.ssl.TLS1_V:
                counters['TLSv1_clients'] += 1
            elif ch.version == dpkt.ssl.TLS11_V:
                counters['TLSv1.1_clients'] += 1
            elif ch.version == dpkt.ssl.TLS12_V:
                counters['TLSv1.2_clients'] += 1

            if len(ch.session_id) > 0:
                counters['session_id_sent'] += 1

            if False:
                print ""
                print 'ch.session_id.version: %s' % dpkt.ssl.ssl3_versions_str[ch.version]
                print 'ch.session_id.len: %d' % len(ch.session_id)
                print 'ch.num_ciphersuites: %d' % ch.num_ciphersuites
                print 'ch.num_compression_methods: %d' % ch.num_compression_methods
                print 'ch.compression_methods: %s' % str(ch.compression_methods)

            if 1 in ch.compression_methods:
                counters['deflate_support'] += 1

    print counters
    return [
        {
            'name': 'SSL v3 Clients',
            'value': as_percent(counters['SSLv3_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1 Clients',
            'value': as_percent(counters['TLSv1_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1.1 Clients',
            'value': as_percent(counters['TLSv1.1_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'TLS v1.2 Clients',
            'value': as_percent(counters['TLSv1.2_clients'], counters['client_hellos_total']),
        },
        {
            'name': 'SessionTicket Support',
            'value': as_percent(counters['session_ticket_support'], counters['client_hellos_total']),
        },
        {
            'name': 'Sent SessionID',
            'value': as_percent(counters['session_id_sent'], counters['client_hellos_total']),
        },
        {
            'name': 'Deflate Support',
            'value': as_percent(counters['deflate_support'], counters['client_hellos_total']),
        }
        ]

def main(argv):
    if len(argv) != 2:
        print "Tool to generate statistics about TLS clients."
        print ""
        print "Usage: parser.py <pcap file>"
        print ""
        sys.exit(1)

    with open(argv[1], 'rb') as fp:
        capture = pcap_reader(fp)
        stats = gather_statistics(capture)

    print ""
    for stat in stats:
        # TODO: CSV, other outputs?
        print "%s: %s" % (stat['name'], stat['value'])

if __name__ == "__main__":
    main(sys.argv)
