# Apple Container Detection

This small C++ program checks whether the current environment looks like Apple Container virtualization.

## What it checks

- Whether the hypervisor compatibility string contains `apple,virtualization-generic-platform`
- Whether `/proc/cmdline` contains `init=/sbin/vminitd`

## Run it

```sh
./run.sh
```

The script builds the program with `g++` using C++17 and executes it inside a containerized Ubuntu environment for illustration purposes.
