#!/usr/bin/python

"""
Modified by Taichi Miya on 2020-08-29.
Copyright (c) 2020 Yamaoka-Kitaguchi Lab. All rights reserved.

Created by Thomas Mangin on 2017-07-06.
Copyright (c) 2009-2017 Exa Networks. All rights reserved.

License: 3-clause BSD
See also: http://blog.sflow.com/2017/07/bgp-flowspec-on-white-box-switch.html
"""

import os
import sys
import json
import re
import subprocess
import signal


class ACL(object):
    dry = os.environ.get('CUMULUS_FLOW_RIB', False)

    chain = "FLOWSPEC"
    interface = "swp1"

    path = '/etc/cumulus/acl/policy.d/'
    priority = '60'
    prefix = 'flowspec'
    bld = '.bld'
    suffix = '.rules'

    __uid = 0
    _known = dict()

    @classmethod
    def _uid(cls):
        cls.__uid += 1
        return cls.__uid

    @classmethod
    def _file(cls, name):
        return cls.path + cls.priority + cls.prefix + str(name) + cls.suffix

    @classmethod
    def _delete(cls, key):
        if key not in cls._known:
            return
        # removing key first so the call to clear never loops forever
        uid, _ = cls._known.pop(key)
        try:
            filename = cls._file(uid)
            if os.path.isfile(filename):
                os.unlink(filename)
        except Exception:
            pass

    @classmethod
    def _commit(cls):
        if cls.dry:
            cls.show()
            return
        try:
            return subprocess.Popen(
                ['cl-acltool', '-i'], stderr=subprocess.STDOUT, stdout=subprocess.PIPE
            ).communicate()[0]
        except Exception:
            pass

    @staticmethod
    def _expand_text_match(protocols):
        # ToDo: Support commas, dots, relational operators and logical operators
        return re.sub('[!<>=]', '', protocols)

    @staticmethod
    def _expand_number_match(ports):
        # ToDo: Support commas, dots, relational operators and logical operators
        return re.sub('[!<>=]', '', ports)

    @classmethod
    def _build_acl(cls, flow, is_ipv4=True, is_drop=False):
        # ToDo: Support commas, dots, relational operators and logical operators
        acl = "[{v}]\n-A {c} -i {i}".format(v="iptables" if is_ipv4 else "ip6tables", c=cls.chain, i=cls.interface)
        if 'protocol' in flow:
            acl += ' -p {p}'.format(p=cls._expand_text_match(flow['protocol'][0]))
        if 'source-ipv4' in flow:
            acl += ' -s {s}'.format(s=flow['source-ipv4'][0])
        if 'destination-ipv4' in flow:
            acl += ' -d {d}'.format(d=flow['destination-ipv4'][0])
        if 'source-ipv6' in flow:
            acl += ' -s {s}'.format(s=flow['source-ipv6'][0])
        if 'destination-ipv6' in flow:
            acl += ' -d {d}'.format(d=flow['destination-ipv6'][0])
        if 'source-port' in flow:
            acl += ' --sport {s}'.format(s=cls._expand_number_match(flow['source-port'][0]))
        if 'destination-port' in flow:
            acl += ' --dport {d}'.format(d=cls._expand_number_match(flow['destination-port'][0]))
        if 'icmp-type' in flow:
            acl += ' --icmp{v}-type {t}'.format(v="" if is_ipv4 else "v6",
                                                t=cls._expand_text_match(flow['icmp-type'][0]))
        acl += ' -j {t}\n'.format(t='DROP' if is_drop else 'ACCEPT')
        return acl

    @classmethod
    def _build(cls, flow, action, is_ipv4):
        acl = {
            None: lambda f: cls._build_acl(f, is_ipv4, is_drop=False),
            'rate-limit:0': lambda f: cls._build_acl(f, is_ipv4, is_drop=True),
        }
        try:
            return acl[action](flow)
        except KeyError:
            pass

    @classmethod
    def insert(cls, flow, action, is_ipv4):
        key = flow['string']
        if key in cls._known:
            return
        uid = cls._uid()
        acl = cls._build(flow, action, is_ipv4)
        cls._known[key] = (uid, acl)
        try:
            with open(cls._file(uid), 'w') as f:
                f.write(acl)
            cls._commit()
        except Exception:
            cls.end()

    @classmethod
    def remove(cls, flow):
        key = flow['string']
        if key not in cls._known:
            return
        cls._delete(key)

    @classmethod
    def clear(cls):
        for key in cls._known:
            cls._delete(key)
        cls._commit()

    @classmethod
    def end(cls):
        cls.clear()
        sys.exit(1)

    @classmethod
    def show(cls):
        for key, (uid, _) in cls._known.items():
            sys.stderr.write('%d %s\n' % (uid, key))
        for _, acl in cls._known.values():
            sys.stderr.write('%s' % acl)
        sys.stderr.flush()


signal.signal(signal.SIGTERM, ACL.end)


opened = 0
buffered = ''

while True:
    try:
        line = sys.stdin.readline()
        if not line or 'shutdown' in line:
            ACL.end()
        buffered += line
        opened += line.count('{')
        opened -= line.count('}')
        if opened:
            continue
        line, buffered = buffered, ''
        message = json.loads(line)

        if message['type'] == 'state' and message['neighbor']['state'] == 'down':
            ACL.clear()
            continue

        if message['type'] != 'update':
            continue

        update = message['neighbor']['message']['update']

        if 'announce' in update:
            announce = update['announce']
            is_ipv4 = True if 'ipv4 flow' in announce else False
            flowlst = announce['ipv4 flow'] if is_ipv4 else announce['ipv6 flow']
            if 'no-nexthop' in flowlst:
                flowlst = flowlst['no-nexthop']
            
            for flow in flowlst:
                community = None
                if 'extended-community' in update['attribute']:
                    community = update['attribute']['extended-community'][0]["string"]
                ACL.insert(flow, community, is_ipv4)
            continue

        if 'withdraw' in update:
            withdraw = update['withdraw']
            is_ipv4 = True if 'ipv4 flow' in withdraw else False
            flowlst = withdraw['ipv4 flow'] if is_ipv4 else withdraw['ipv6 flow']
            
            for flow in flowlst:
                ACL.remove(flow)
            continue

    except KeyboardInterrupt:
        ACL.end()
    except Exception:
        pass
