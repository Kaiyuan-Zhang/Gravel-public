import subprocess as sp
import sys
import os


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: {} <element-list> <ele-dir> <conf-ele-list>".format(sys.argv[0]))
        sys.exit(-1)

    ele_list_fn = sys.argv[1]
    ele_dir = sys.argv[2]
    conf_ele_list = sys.argv[3]

    ele_fn_map = {}
    with open(ele_list_fn, 'r') as f:
        for l in f.readlines():
           words = l.rstrip().split()
           assert words[1] not in ele_fn_map
           ele_fn_map[words[1]] = words[0]

    conf_eles = set()
    with open(conf_ele_list, 'r') as f:
        for l in f.readlines():
            conf_eles.add(l.rstrip())

    args = []
    for e in conf_eles:
        if e in ele_fn_map:
            args.append(os.path.join(ele_dir, ele_fn_map[e]))

    cmd = ['cloc'] + args
    p = sp.Popen(cmd)
    p.communicate()
