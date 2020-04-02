import pandas
import sys
import os
import argparse


def process_record(lines):
    # (ele_name, (state_ok, +arr, +obj))
    ele_name = None
    supported = False
    arr = False
    obj = False
    for l in lines:
        if l.startswith("Processing:"):
            words = l.rstrip().split()
            ele_name = words[1]
        elif l.startswith("ENTRY:"):
            if l.find("PUSH") < 0:
                return None
        elif l.startswith("DONE:"):
            need_arr = False
            need_obj = False
            if l.find("AbstractDataType") >= 0:
                need_obj = True
            if l.find("Fix-sized Array") >= 0:
                need_arr = True
            if need_arr or need_obj:
                supported = False
            else:
                supported = True
            arr = not need_obj
            obj = True
    return (ele_name, (supported, arr, obj))


def load_ele_list(fn):
    result = set()
    with open(fn, 'r') as f:
        lines = f.readlines()
        for l in lines:
            result.add(l.rstrip())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process element log')
    parser.add_argument('compat_log', type=str)
    parser.add_argument('conf_list_file', type=str)
    parser.add_argument('conf_dir', type=str)
    parser.add_argument('element_list', type=str, nargs='+')

    args = parser.parse_args()

    compat_log = args.compat_log

    element_record = {}
    with open(compat_log, 'r') as f:
        lines = f.readlines()
        curr = 0
        while curr < len(lines):
            l = lines[curr]
            next = curr + 1
            if l.startswith('=========='):
                # now try to find next '======='
                while (not lines[next].startswith('==========')) and next < len(lines):
                    next += 1
                region = lines[curr+1:next]
                result = process_record(region)        

                if result is not None:
                    element_record[result[0]] = result[1]
                next += 1
            curr = next

    element_list = []

    for fn in args.element_list:
        element_list += load_ele_list(fn)

    conf_list = load_ele_list(args.conf_list_file)
    ok_conf = []

    offensive = {}
    for c in conf_list:
        e_list_fn = os.path.join(args.conf_dir, c)
        used_eles = load_ele_list(e_list_fn)

        supported = True
        for e in used_eles:
            if e in element_record and e not in element_list:
                supported = False
                if e not in offensive:
                    offensive[e] = 0
                offensive[e] += 1
        if supported:
            ok_conf.append(c)
    
    print("Support {} / {} ({}%) configurations".format(len(ok_conf), len(conf_list), len(ok_conf) / float(len(conf_list)) * 100))

    sorted_eles = sorted(offensive.items(), key = lambda x : x[1])
    for e in sorted_eles[::-1]:
        print(e[0], e[1])
