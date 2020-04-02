import sys
import os


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: {} <conf-list> <conf-dir> [black-list-files]".format(sys.argv[0]))
        sys.exit(-1)
    conf_list_file = sys.argv[1]
    conf_dir = sys.argv[2]
    conf_list = {}
    black_list_files = sys.argv[3:]
    ele_black_list = set()
    for fn in black_list_files:
        with open(fn, 'r') as f:
            lines = f.readlines()
            for l in lines:
                ele_black_list.add(l.rstrip())

    with open(conf_list_file, 'r') as f:
        lines = f.readlines()
        for l in lines:
            fn = os.path.join(conf_dir, l.rstrip())
            with open(fn, 'r') as conf_f:
                elements = conf_f.readlines()
                conf_list[l] = list(map(lambda s: s.rstrip(), elements))
    
    offensive = {}
    if "InfiniteSource" in ele_black_list:
        ele_black_list.remove("InfiniteSource")
    for e in ele_black_list:
        offensive[e] = 0
    supported = []
    for conf, eles in conf_list.items():
        in_list = False
        for e in eles:
            if e in ele_black_list:
                in_list = True
                offensive[e] += 1
        if not in_list:
            supported.append(conf)
    ratio = float(len(supported)) / float(len(conf_list.keys())) * 100.0
    sorted_eles = sorted(offensive.items(), key = lambda x : x[1])
    print("Support {} / {} ({}%) Confs".format(len(supported), len(conf_list.keys()), ratio))
    #print(sorted_eles[:-10:-1])
    for e in sorted_eles[::-1]:
        print(e[0], e[1])
