import sys
import os

def remove_line_comment(line):
    p = line.find('//')
    if p != -1:
        return line[0:p]
    else:
        return line

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <click-conf-file>".format(sys.argv[0]))
        sys.exit(-1)
    conf_file = sys.argv[1]
    elements = set()
    with open(conf_file, 'r') as f:
        lines = f.readlines()
        content = ''

        # remove '//' comment
        for l in lines:
            content += remove_line_comment(l)

        # remove '/* ... */' comment
        i = 0
        new_content = ''
        while i < len(content):
            if i < len(content) - 1 and content[i:i+2] == '/*':
                # find the first '*/'
                j = i+3
                while j < len(content):
                    if content[j-1:j+1] == '*/':
                        break
                    j = j+1
                i = j+1
            new_content += content[i]
            i += 1
        content = new_content
        for i, c in enumerate(content):
            if c == '(':
                # search back for space or ':'
                j = i
                while j >= 0:
                    if content[j].isspace():
                        break
                    if content[j] in ['\n', '\r']:
                        break
                    if content[j] in [':', '>']:
                        break
                    j -= 1
                elements.add(content[j+1:i])
    for e in elements:
        print(e)
