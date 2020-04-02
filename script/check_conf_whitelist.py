import sys
import os


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: {} <conf-list> <conf-dir> [white-list-files]".format(sys.argv[0]))
        sys.exit(-1)
    conf_list_file = sys.argv[1]
    conf_dir = sys.argv[2]
    conf_list = {}
    white_list_files = sys.argv[3:]
    ele_white_list = set()
    for fn in white_list_files:
        with open(fn, 'r') as f:
            lines = f.readlines()
            for l in lines:
                ele_white_list.add(l.rstrip())

    with open(conf_list_file, 'r') as f:
        lines = f.readlines()
        for l in lines:
            fn = os.path.join(conf_dir, l.rstrip())
            with open(fn, 'r') as conf_f:
                elements = conf_f.readlines()
                conf_list[l] = list(map(lambda s: s.rstrip(), elements))
    
    offensive = {}
    supported = []
    for conf, eles in conf_list.items():
        can_not_run = False
        for e in eles:
            if e not in ele_white_list:
                can_not_run = True
                if e not in offensive:
                    offensive[e] = 0
                offensive[e] += 1
        if not can_not_run:
            supported.append(conf)

    ratio = float(len(supported)) / float(len(conf_list.keys())) * 100.0
    sorted_eles = sorted(offensive.items(), key = lambda x : x[1])
    print("Support {} / {} ({}%) Confs".format(len(supported), len(conf_list.keys()), ratio))

    for e in sorted_eles[::-1]:
        print(e[0], e[1])
