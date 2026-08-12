#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

const std::string_view kAppleVirtualizationCompatible =
    "apple,virtualization-generic-platform";
const std::string kHypervisorCompatiblePaths[] = {
    "/proc/device-tree/hypervisor/compatible",
    "/sys/firmware/devicetree/base/hypervisor/compatible"
};
const std::string kVminitdArgument = "init=/sbin/vminitd";

std::optional<std::string> readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

bool IsAppleVirtualizationCompatible() {
    // macOS Virtualization.framework creates this device-tree compatibility string.
    // Linux exposes it through /proc/device-tree/hypervisor/compatible.
    // It identifies Apple’s generic virtual-machine platform, not Apple containers specifically.
    for (const auto& path : kHypervisorCompatiblePaths) {
        const auto compatible = readFile(path);
        if (!compatible) {
            continue;
        }
        if (compatible->find(kAppleVirtualizationCompatible) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool IsVminitdArgumentPresent() {
    // Apple Containerization boots its guest with "init=/sbin/vminitd":
    // https://github.com/apple/containerization/blob/0.33.3/Sources/Containerization/VZVirtualMachineInstance.swift#L569-L599
    // Linux exposes kernel boot arguments via /proc/cmdline: https://man7.org/linux/man-pages/man5/proc_cmdline.5.html
    const auto bootArgs = readFile("/proc/cmdline");
    if (!bootArgs) {
        return false;
    }
    return bootArgs->find(kVminitdArgument) != std::string::npos;
}



int main() {
    std::cout << "----------------------------------------------------------------\n";
    std::cout << "Checking for traces of Apple containerization...\n";
    std::cout << "Apple virtualization compatible: " << (IsAppleVirtualizationCompatible() ? "True" : "False") << '\n';
    std::cout << "vminitd argument present in /proc/cmdline: " << (IsVminitdArgumentPresent() ? "True" : "False") << '\n';
    std::cout << "----------------------------------------------------------------\n";
    return 0;
}
