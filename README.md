# Gravel: Automated Verification Framework for Customized Middlebox Properties

This is the source code repository of the Gravel project.
Check out [our paper](https://www.usenix.org/system/files/nsdi20-paper-zhang_kaiyuan.pdf) for more details

## Directory Structure

Subdirectory      | Description
------------------| ---------------
`include/`        | Symbolic executor headers
`src/`            | Symbolic executor sources
`exec/`           | Source for executables and unit tests
`py/`             | Python library for the high-level specification DSL and configuration verifier
`specs/`          | High-level and element-level specifications for our example middleboxes
`ir-helpers.tar.gz` | A set of scripts we used to produce LLVM IR file for verification.

include/ C++ headers for symbolic executor
src/ C++ source code for symbolic executor
exec/ symbolic executor executables and some unit tests
py/ Python library for the high-level specification DSL and configuration verifier
specs/ High-level and element-level specifications for our example middleboxes

## Build Instruction
### System Requirements
Gravel requires Boost, LLVM, and Z3. The current version works with both LLVM-9.0 and LLVM-6.0

### High-level verifier
The high-level verifier is implemented in Python and therefore does not require compiling. To import it into your own Python program, update the PYTHONPATH by
```bash
export PYTHONPATH=$(pwd)/py/:$PYTHONPATH
```
Then use
```python
import gravel_spec
```
in python to import the high-level verifier


### Symbolic Executor
Gravel uses cmake for building the symbolic executor binaray and library.

```bash
mkdir build
cd build
cmake ..
```
Then run
```bash
make -j
```
to build the symbolic executor

## Verification
### High-level verifier
To run verifier on the five example middleboxes, run:
```bash
make run_toplevel SPEC=[spec-file]
```

For example, to verify the NAT example, use the following command:
```bash
make run_toplevel SPEC=specs/mazu-nat.py
```

### Element-level verifier
Each element-level verification task in Gravel is implemented as a Python unittest. Developers could call the `verify_pkt_handler` method of each element with a path to the LLVM IR souce file. The verifier will perform symbolic execution on the LLVM IR and compare the behavior of implementation and element-level specification.

For example, the following command asks the verifier to verify the IPRewriter element used in NAT:
```bash
# first untar the archive to extract the IR file for element
mkdir ir-dir
tar zxvf ir-helpers.tar.gz -C ir-dir
# now run the verifier
make run_element_task TASK=specs/verify-rewriter.py
```
Note: use `ir-helpers-llvm60.tar.gz` if you are using LLVM 6.0

## Verify your own middleboxes
To verify you own middlebox implementation using Gravel, 
you'll need to provide the following inputs to Gravel:

### High-level specification
Please refer to our paper and the top-level specifications given in `specs/` directory on how to use Gravel's high-level specifcation API.

### Element-level specification
A state machine representation of each Click element.
Developers could specify element behavior by implementing a sub-class of `ClickElement` class.
Please refer to example Click elements in `py/gravel_spec/click_common.py` for sample element-level specifications.

### Implementation
Gravel runs symbolic execution on the compiled LLVM IR code of each Click elements.
LLVM IR could be obtained by compiling the element source file with `-S -emit-llvm` flag of `clang++`.

We've also included a version of compiled IR files in the tar archive.

## LLVM IR files for Click elements
The `ir-helpers.tar.gz` file archives a set of scripts that could be used to generate LLVM IR file from Click's source tree.
We've already included the compiled IR file so that there is no need to recompile Click if you only want to run element-level verification.
The `all.ll` file in the archive combines the IR code for all Click elements into a single file.

To generate IR file for you own Click element, untar the file under a newly created directory in Click source tree:
```bash
cd [diretory-to-click]
mkdir ir-helpers # or any directory name you'd like to use
tar [path-to-gravel]/ir-helpers.tar.gz -C ir-helpers
```

Then use
```bash
make -j
```
to produce the IR files.
