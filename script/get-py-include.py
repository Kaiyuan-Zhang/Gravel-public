#!/usr/bin/env python3

from sysconfig import get_paths
from pprint import pprint

info = get_paths()  # a dictionary of key-paths

print(info['include'])
