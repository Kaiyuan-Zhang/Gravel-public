#include "utils.hpp"


int main(int argc, char *argv[]) {
    std::cout << is_prefix("1321321321", "13213") << " "
              << is_prefix("1321321321", "13212") << std::endl;
    return 0;
}
