import Darwin
import Foundation
@preconcurrency import Virtualization

private enum RunnerError: Error, CustomStringConvertible {
    case usage(String)
    case invalidFile(String)
    case unsupported(String)
    case runtime(String)

    var description: String {
        switch self {
        case .usage(let message), .invalidFile(let message),
             .unsupported(let message), .runtime(let message):
            return message
        }
    }
}

private struct Options {
    let kernel: URL
    let initialRamdisk: URL
    let disk: URL?
    let network: Bool

    private static let usage =
        "usage: vz-linux-runner [--disk RAW] [--network] KERNEL INITRAMFS"

    static func parse(_ arguments: [String]) throws -> Options {
        var diskPath: String?
        var network = false
        var positional: [String] = []
        var index = 1

        while index < arguments.count {
            switch arguments[index] {
            case "--disk":
                index += 1
                guard index < arguments.count else {
                    throw RunnerError.usage("--disk requires a path\n\(usage)")
                }
                diskPath = arguments[index]
            case "--network":
                network = true
            case "-h", "--help":
                throw RunnerError.usage(usage)
            default:
                guard !arguments[index].hasPrefix("-") else {
                    throw RunnerError.usage(
                        "unknown option: \(arguments[index])\n\(usage)"
                    )
                }
                positional.append(arguments[index])
            }
            index += 1
        }

        guard positional.count == 2 else {
            throw RunnerError.usage(usage)
        }
        return Options(
            kernel: URL(fileURLWithPath: positional[0]).standardizedFileURL,
            initialRamdisk: URL(fileURLWithPath: positional[1]).standardizedFileURL,
            disk: diskPath.map {
                URL(fileURLWithPath: $0).standardizedFileURL
            },
            network: network
        )
    }
}

private func validateRegularFile(_ url: URL, label: String) throws {
    let attributes: [FileAttributeKey: Any]
    do {
        attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    } catch {
        throw RunnerError.invalidFile("cannot inspect \(label) \(url.path): \(error)")
    }
    guard attributes[.type] as? FileAttributeType == .typeRegular else {
        throw RunnerError.invalidFile("\(label) is not a regular file: \(url.path)")
    }
    guard let size = attributes[.size] as? NSNumber, size.uint64Value > 0 else {
        throw RunnerError.invalidFile("\(label) is empty: \(url.path)")
    }
}

private func makeConfiguration(_ options: Options) throws -> VZVirtualMachineConfiguration {
    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle.standardInput,
        fileHandleForWriting: FileHandle.standardOutput
    )

    let loader = VZLinuxBootLoader(kernelURL: options.kernel)
    loader.initialRamdiskURL = options.initialRamdisk
    loader.commandLine = "console=hvc0 rdinit=/bin/sh"

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = VZGenericPlatformConfiguration()
    configuration.bootLoader = loader
    configuration.cpuCount = VZVirtualMachineConfiguration.minimumAllowedCPUCount
    configuration.memorySize = max(
        VZVirtualMachineConfiguration.minimumAllowedMemorySize,
        512 * 1024 * 1024
    )
    configuration.serialPorts = [serial]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

    if let disk = options.disk {
        let attachment = try VZDiskImageStorageDeviceAttachment(
            url: disk,
            readOnly: false,
            cachingMode: .automatic,
            synchronizationMode: .full
        )
        configuration.storageDevices = [
            VZVirtioBlockDeviceConfiguration(attachment: attachment)
        ]
    }

    if options.network {
        let device = VZVirtioNetworkDeviceConfiguration()
        device.macAddress = VZMACAddress.randomLocallyAdministered()
        device.attachment = VZNATNetworkDeviceAttachment()
        configuration.networkDevices = [device]
    }

    try configuration.validate()
    return configuration
}

private func start(_ vm: VZVirtualMachine, on queue: DispatchQueue) async throws {
    try await withCheckedThrowingContinuation { continuation in
        queue.sync {
            vm.start { result in
                continuation.resume(with: result)
            }
        }
    }
}

@main
private struct VZLinuxRunner {
    static func main() async {
        do {
            guard VZVirtualMachine.isSupported else {
                throw RunnerError.unsupported(
                    "Virtualization.framework is unavailable on this Mac"
                )
            }

            let options = try Options.parse(CommandLine.arguments)
            try validateRegularFile(options.kernel, label: "kernel")
            try validateRegularFile(options.initialRamdisk, label: "initramfs")
            if let disk = options.disk {
                try validateRegularFile(disk, label: "disk")
            }

            let configuration = try makeConfiguration(options)
            let queue = DispatchQueue(label: "com.tbarabosch.vz-linux-runner")
            let vm = VZVirtualMachine(configuration: configuration, queue: queue)

            FileHandle.standardError.write(
                Data("Starting the Linux VM; use 'poweroff -f' to stop it.\n".utf8)
            )
            try await start(vm, on: queue)

            while true {
                switch queue.sync(execute: { vm.state }) {
                case .stopped:
                    FileHandle.standardError.write(Data("Linux VM stopped.\n".utf8))
                    return
                case .error:
                    throw RunnerError.runtime("the Linux VM entered the error state")
                default:
                    usleep(100_000)
                }
            }
        } catch {
            FileHandle.standardError.write(Data("error: \(error)\n".utf8))
            exit(EXIT_FAILURE)
        }
    }
}
