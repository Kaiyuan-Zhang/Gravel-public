CC = clang
CXX = clang++
MAKE = make
AR = ar
LD = ld

LLVM_CONFIG := llvm-config

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CC = gcc-7
CXX = g++-7
LLVM_CONFIG := /usr/local/opt/llvm/bin/llvm-config
endif

LLVM_LIBDIR := $(shell "$(LLVM_CONFIG)" --libdir)
LLVM_LIBS := $(shell "$(LLVM_CONFIG)" --libs)
LLVM_SYSLIBS := $(shell "$(LLVM_CONFIG)" --system-libs)

BASE_DIR = $(shell pwd)
INC_DIR = include
#LINUX_INC_DIR = linux_headers
SRC_DIR = src
EXEC_DIR = exec
TEST_DIR = test
OBJ_DIR = obj
BIN_DIR = bin

INC_FLAGS = -I$(INC_DIR) 

ifeq ($(UNAME_S),Darwin)
INC_FLAGS += -I$(shell "$(LLVM_CONFIG)" --includedir)
endif

PY_INCDIR := $(shell "$(PWD)/script/get-py-include.py")
INC_FLAGS += -I$(PY_INCDIR)

CXXFLAGS = -std=c++1z -O3 $(INC_FLAGS) -MMD -Wno-unused-command-line-argument -fPIC
CFLAGS = -O3 $(INC_FLAGS) -MMD -Wno-unused-command-line-argument
LDFLAGS = -L/usr/lib -lz3

ifeq ($(DEBUG),1)
CXXFLAGS := -std=c++1z -O0 -g $(INC_FLAGS) -MMD -Wno-unused-command-line-argument -fPIC
endif

UNAME := $(shell uname)

ifeq ($(UANME),Linux)
	LDFLAGS += -L/usr/lib/
endif

HEADERS := $(wildcard include/*.hpp)
HEADERS += $(wildcard include/*.h)

SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
OBJ_FILES := $(subst $(SRC_DIR)/,,$(SRC_FILES:%.cpp=$(OBJ_DIR)/%.o))
DEP = $(OBJ_FILES:%.o=%.d)

C_SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES += $(subst $(SRC_DIR)/,,$(C_SRC_FILES:%.c=$(OBJ_DIR)/%.o))

LIB_NAME := libcobble.a
SO_NAME := libcobble.so

TEST_FILES := $(wildcard $(TEST_DIR)/*.cpp)
TESTS := $(subst $(TEST_DIR)/,,$(TEST_FILES:%.cpp=$(BIN_DIR)/%))

EXEC_FILES := $(wildcard $(EXEC_DIR)/*.cpp)
BINS := $(subst $(EXEC_DIR)/,,$(EXEC_FILES:%.cpp=$(BIN_DIR)/%))

all: $(OBJ_DIR) $(BIN_DIR) $(LIB_NAME) $(SO_NAME) $(BINS)

debug: CXXFLAGS := -std=c++1z -O0 -g $(INC_FLAGS) -MMD -Wno-unused-command-line-argument -fPIC
debug: all

-include $(DEP)

$(LIB_NAME): $(OBJ_FILES)
	$(AR) cr $@ $^

$(SO_NAME): $(OBJ_FILES)
	$(CXX) $(CXXFLAGS) -stdlib=libc++ -shared -o $@ $^ $(LDFLAGS)

$(OBJ_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $< $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $< $(LDFLAGS)

$(BIN_DIR)/% : $(EXEC_DIR)/%.cpp $(LIB_NAME)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_NAME) $(LDFLAGS) -L$(LLVM_LIBDIR) $(LLVM_LIBS) $(LLVM_SYSLIBS)

# $(BIN_DIR)/% : $(TEST_DIR)/%.cpp $(LIB_NAME)
# 	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_NAME) $(LDFLAGS) -L$(LLVM_LIBDIR) $(LLVM_LIBS) $(LLVM_SYSLIBS)

.PHONY: clean all run_toplevel

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

# some commands for running python
NEW_PY_PATH := $(CURDIR)/py
PYTHON := env python3

run_toplevel:
	PYTHONPATH=$(NEW_PY_PATH)/:$$PYTHONPATH $(PYTHON) -m unittest -v $(SPEC)

run_element_task:
	PYTHONPATH=$(NEW_PY_PATH)/:$$PYTHONPATH $(PYTHON) -m unittest -v $(TASK)
