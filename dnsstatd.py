#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012, Torbjörn Lönnemark <tobbez@ryara.net>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from __future__ import print_function

import os
import netifaces
import ConfigParser
import pcap # python-libpcap on debian, pylibpcap on gentoo
import dpkt
import dnslib
import psycopg2
import logging
import time
import traceback

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

__dbconnection = None
__dbconnect = None

def check_config(config):
    required = ['dev', 'db_dsn']
    for k in required:
        if not config.has_option('dnsstatd', k):
            return False
    return True

def handle_packet(length, data, timestamp):
    global __dbconnect
    global __dbconnection
    try:
        parse_and_save_packet(data, timestamp)
    except (KeyboardInterrupt, SystemExit):
        raise
    except psycopg2.OperationalError as ope:
        logging.error('Failed to insert data into database: %s', ope.message)
        logging.info('Trying to reconnect')
        connected = False
        while not connected:
            time.sleep(5)
            try:
                __dbconnect()
                connected = True
            except Exception as e:
                pass
        logging.info('Reconnected')

    except Exception as e:
        enc_data = data.encode('hex')
        __dbconnection.rollback()
        cur = __dbconnection.cursor()
        cur.execute('INSERT INTO dnsstatd_failure (ts, error, packet) VALUES (to_timestamp(%s), %s, %s)', (timestamp, traceback.format_exc(), enc_data))
        __dbconnection.commit()
        logging.warning('Unhandled exception logged to database: %s', e)

def parse_and_save_packet(data, timestamp):
    global __dbconnection
    eth = dpkt.ethernet.Ethernet(data)
    ip = eth.data
    udp = ip.data
    #print(udp.data.encode('hex'))
    dns = dnslib.DNSRecord.parse(udp.data)
    if not (dns.header.opcode == dnslib.OPCODE.lookup('QUERY') and dns.header.qr == dnslib.QR.lookup('RESPONSE')):
        return

    def format_ip(s):
        if len(s) == 4:
                return '.'.join(map(lambda x: str(ord(x)), s))
        hexes = map(lambda x: '{:02x}'.format(ord(x)), s)
        return ':'.join([''.join(hexes[i:i+2]) for i in xrange(0, len(hexes), 2)])


    cur = __dbconnection.cursor()
    cur.execute('INSERT INTO dnsstatd_response (hdrid, ts, rcode, aa, tc, rd, ra, client, server)'
            + ' VALUES (%s, to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s) RETURNING id',
            (dns.header.id, timestamp, dns.header.rcode, bool(dns.header.aa), bool(dns.header.tc),
                bool(dns.header.rd), bool(dns.header.ra), format_ip(ip.dst), format_ip(ip.src)))
    resp_id = cur.fetchone()[0]

    for q in dns.questions:
        cur.execute('INSERT INTO dnsstatd_question (response, name, type, class) VALUES (%s, %s, %s, %s)',
                (resp_id, str(q.qname), q.qtype, q.qclass))

    for rr in dns.rr:
        cur.execute('INSERT INTO dnsstatd_resource_record (response, name, type, class, ttl, rdata) VALUES (%s, %s, %s, %s, %s, %s)',
                (resp_id, str(rr.rname), rr.rtype, rr.rclass, rr.ttl, str(rr.rdata)))
    __dbconnection.commit()


def main(args):
    global __dbconnection
    global __dbconnect

    if '-h' in args or '--help' in args:
        print ('Usage: {}'.format(args[0]))

    script_path = os.path.dirname(args[0])

    config = ConfigParser.RawConfigParser()
    try:
        config.read(os.path.join(script_path, 'config'))
    except:
        logging.error("Couldn't read configuration file")
        return

    if not check_config(config):
        logging.error("Configuration files is missing one or more values")
        return

    def create_dbconnect():
        dsn = config.get('dnsstatd', 'db_dsn')
        def dbc():
            global __dbconnection
            __dbconnection = psycopg2.connect(dsn)
            logging.info("Database connection established")
        return dbc

    __dbconnect = create_dbconnect()


    try:
        __dbconnect()
    except psycopg2.DatabaseError as dbe:
        logging.error("Error connecting to database: %s", dbe.message)
        return

    #logging.info("Database connection established")



    addrs = []
    cap_dev = 'any'
    ifaces = config.get('dnsstatd', 'dev').split(',')
    if len(ifaces) == 1:
        cap_dev = ifaces[0]
    if ifaces[0] == 'any':
        ifaces = netifaces.interfaces()
    for iface in ifaces:
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            addrs.append(addr['addr'])
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET6, []):
            if not '%' in addr['addr']:
                addrs.append(addr['addr'])
    
    pcap_filter = 'src port 53 and ({})'.format(' or '.join(['src ' + x for x in addrs]))

    p = pcap.pcapObject()
    #_, _ = pcap.lookupnet(iface)
    p.open_live(cap_dev, 8192, 0, 100)

    p.setfilter(pcap_filter, 0, 0)
    p.setnonblock(0)

    logging.info("Listening on {} using filter \"{}\"".format(cap_dev, pcap_filter))
    logging.warning("python-libpcap will not release after SIGTERM until receieving one more packet")

    try:
        p.loop(0, handle_packet)
    except KeyboardInterrupt:
        logging.info('Caught signal, shutting down')
        logging.info('{} packets, {} dropped, {} dropped by interface'.format(*p.stats()))
    

if __name__ == '__main__':
    import sys
    main(sys.argv)
