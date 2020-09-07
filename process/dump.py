#!/usr/bin/python

import sys
import time

buffered, opened = "", 0
while True:
    line = sys.stdin.readline()
    buffered += line
    opened += line.count('{')
    opened -= line.count('}')
    if opened:
        continue

    tstamp = int(time.time() * 1000)
    with open("/tmp/message-{}.json".format(tstamp), 'w') as fd:
        fd.write(buffered)
