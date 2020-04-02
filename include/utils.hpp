#pragma once

#include <iostream>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>


bool is_prefix(const std::string &s, const std::string &prefix);

class NameFactory {
    std::unordered_map<std::string, uint64_t> name_map_;
public:
    std::string GetUniqueName(const std::string &base_name);
    std::string gen(const std::string &base_name) {
        return GetUniqueName(base_name);
    }
    std::string operator()(const std::string &base_name) {
	return GetUniqueName(base_name);
    }
};

class SubProcessFunc {
public:
    struct Exception {
	std::string msg;
    };
    
    SubProcessFunc(std::function<std::string()> f);
    std::string operator()();

protected:
    std::function<std::string()> f_;
};
