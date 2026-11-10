#pragma once

#include <string>
#include <vector>

namespace datastego {
class CLIController {
public:
    int run(const std::vector<std::string>& arguments) const;
private:
    int runInteractive() const;
};
}
