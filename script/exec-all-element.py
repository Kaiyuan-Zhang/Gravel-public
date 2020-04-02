import sys
import os
import subprocess as sp
import argparse


def cc_to_ll(fn):
    pre, ext = os.path.splitext(fn)
    return pre + ".ll"


DEFAULT_CMD_PROG = './bin/check-state-compat'

def run_cmd_on_element(ll_file, element_name, cmd):
    global CMD_PROG
    print('===============================')
    proc = sp.Popen([cmd, ll_file, element_name], stdout=sp.PIPE, stderr=sp.PIPE)
    out, err = proc.communicate()
    out, err = out.decode('utf-8'), err.decode('utf-8')
    print(out, '\n', err)
    print('===============================')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='execute command on all elements')
    parser.add_argument('element_list', type=str)
    parser.add_argument('ir_dir', type=str)
    parser.add_argument('--cmd', dest='cmd', default=DEFAULT_CMD_PROG)

    args = parser.parse_args()

    list_file = args.element_list
    ir_dir = args.ir_dir
    with open(list_file, 'r') as f:
        lines = f.readlines()
        for l in lines:
            words = l.split()
            ll_file = cc_to_ll(words[0])
            ele_name = words[1]
            run_cmd_on_element(os.path.join(ir_dir, ll_file), ele_name, args.cmd)
