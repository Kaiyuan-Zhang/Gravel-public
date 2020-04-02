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
    parser.add_argument('element_list', type=str)
    parser.add_argument('compat_log', type=str)
    parser.add_argument('loop_base', type=str)
    parser.add_argument('loop_opt', type=str)

    args = parser.parse_args()

    list_file = args.element_list
    compat_log = args.compat_log

    loop_base = load_ele_list(args.loop_base)
    loop_opt = load_ele_list(args.loop_opt)

    element_record = {}

    with open(list_file, 'r') as f:
        lines = f.readlines()
        for l in lines:
            words = l.split()
            ele_name = words[1]
            element_record[ele_name] = list()

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

    num_tot = len(element_record)
    
    ptr_forbid = set()
    for e, r in element_record.items():
        if not r[0]:
            ptr_forbid.add(e)

    print("Not supported Ptr: {}; Loop: {}".format(len(ptr_forbid), len(loop_base)))

    num_base = 0
    num_w_arr = 0
    num_w_obj = 0
    for e in loop_base:
        if e in element_record:
            element_record[e] = (False, False, False)

    for e, r in element_record.items():
        if r[0]:
            num_base += 1
        if r[1]:
            num_w_arr += 1
        if r[2]:
            num_w_obj += 1

    print("Total Elements: {}".format(len(element_record)))
    print("Base: {} / {} ({}%)".format(num_base, num_tot, num_base / float(num_tot) * 100.0))
    print("W/ Arr: {} / {} ({}%)".format(num_w_arr, num_tot, num_w_arr / float(num_tot) * 100.0))
    print("W/ Obj: {} / {} ({}%)".format(num_w_obj, num_tot, num_w_obj / float(num_tot) * 100.0))

    for e, r in element_record.items():
        if not r[2]:
            print(e)

    # for e, r in element_record.items():
    #     if r[2]:
    #         print(e)
