import sys
import os


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: {} <conf-list> <conf-dir>".format(sys.argv[0]))
        sys.exit(-1)
    conf_list_file = sys.argv[1]
    conf_dir = sys.argv[2]

    all_elements = set()
    element_cnt = {}

    with open(conf_list_file, 'r') as f:
        lines = f.readlines()
        for l in lines:
            fn = os.path.join(conf_dir, l.rstrip())
            with open(fn, 'r') as conf_f:
                elements = conf_f.readlines()
                for e in elements:
                    name = e.rstrip()
                    all_elements.add(name)
                    if name not in element_cnt:
                        element_cnt[name] = 0
                    element_cnt[name] += 1
   
    sorted_eles = sorted(element_cnt.items(), key = lambda x: x[1])
    for entry in sorted_eles[::-1]:
        print(entry[0], ',', entry[1])
