package main

import (
	"encoding/json"
	"os"
	"path"
	"regexp"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/specs"
)

var bundleValidateFlags = []cli.Flag{
	cli.StringFlag{Name: "path", Usage: "path to the bundle (could either be a directory or an archived file)"},
}

var bundleValidateCommand = cli.Command{
	Name:  "bundleValidate",
	Usage: "validate a OCI bundle",
	Flags: bundleValidateFlags,
	Action: func(context *cli.Context) {
		inputPath := context.String("path")
		if inputPath == "" {
			logrus.Fatalf("Bundle path shouldn't be empty")
		}

		if fi, err := os.Stat(inputPath); err != nil {
			logrus.Fatal(err)
		} else if !fi.IsDir() {
			logrus.Fatalf("Archival format is not defined in OCI yet.")
		}

		sf, err := os.Open(path.Join(inputPath, "config.json"))
		if err != nil {
			logrus.Fatal(err)
		}

		defer sf.Close()

		//TODO: Using protobuf to decode spec, so the 'required' config will be checked automaticly
		var spec specs.LinuxSpec
		if err = json.NewDecoder(sf).Decode(&spec); err != nil {
			logrus.Fatal(err)
		} else {
			if spec.Platform.OS != "linux" {
				logrus.Fatalf("Operation system '%s' of the bundle is not support yet.", spec.Platform.OS)
			}
		}

		//TODO: Using protobuf to decode spec, so the 'required' config will be checked automaticly
		rf, err := os.Open(path.Join(inputPath, "runtime.json"))
		if err != nil {
			logrus.Fatal(err)
		}
		defer rf.Close()

		var runtime specs.LinuxRuntimeSpec
		if err = json.NewDecoder(rf).Decode(&runtime); err != nil {
			logrus.Fatal(err)
		}

		bundleValidate(spec, runtime, path.Join(inputPath, "rootfs"))
		logrus.Infof("Bundle validate succeeded.")
	},
}

func bundleValidate(spec specs.LinuxSpec, runtime specs.LinuxRuntimeSpec, rootfs string) {
	CheckSemVer(spec.Version)
	CheckMountPoints(spec.Mounts, runtime.Mounts, rootfs)
	CheckLinuxSpec(spec, runtime)
	CheckLinuxRuntime(runtime.Linux, rootfs)
}

func CheckSemVer(version string) {
	re, _ := regexp.Compile("^(\\d+)?\\.(\\d+)?\\.(\\d+)?$")
	if ok := re.Match([]byte(version)); !ok {
		logrus.Fatalf("%s is not a valid version format, please read 'SemVer v2.0.0'", version)
	}
}

func CheckMountPoints(mps []specs.MountPoint, rmps map[string]specs.Mount, rootfs string) {
	for index := 0; index < len(mps); index++ {
		mountPath := path.Join(rootfs, mps[index].Path)
		if fi, err := os.Stat(mountPath); err != nil {
			logrus.Fatal(err)
		} else if !fi.IsDir() {
			logrus.Fatalf("Mount point %s is not a valid directory", mountPath)
		}

		if _, ok := rmps[mps[index].Name]; !ok {
			logrus.Fatalf("%s in config/mount does not exist in runtime/mount", mps[index].Name)
		}
	}
}

//Linux only
func CheckLinuxSpec(spec specs.LinuxSpec, runtime specs.LinuxRuntimeSpec) {
	paths := requiredPaths()
	for pIndex := 0; pIndex < len(paths); pIndex++ {
		found := false
		for mIndex := 0; mIndex < len(spec.Spec.Mounts); mIndex++ {
			mp := spec.Spec.Mounts[mIndex]
			if paths[pIndex] == mp.Path {
				found = true
				break
			}
		}
		if !found {
			logrus.Fatalf("Mount %s is missing.", paths[pIndex])
		}
	}

	for index := 0; index < len(spec.Linux.Capabilities); index++ {
		capability := spec.Linux.Capabilities[index]
		if !capValid(capability) {
			logrus.Fatalf("%s is not valid, man capabilities(7)", spec.Linux.Capabilities[index])
		}
	}
}

//Linux only
func CheckLinuxRuntime(runtime specs.LinuxRuntime, rootfs string) {
	if len(runtime.UIDMappings) > 5 {
		logrus.Fatalf("Only 5 UID mappings are allowed (linux kernel restriction).")
	}
	if len(runtime.GIDMappings) > 5 {
		logrus.Fatalf("Only 5 GID mappings are allowed (linux kernel restriction).")
	}

	for index := 0; index < len(runtime.Rlimits); index++ {
		if !rlimitValid(runtime.Rlimits[index].Type) {
			logrus.Fatalf("Rlimit %s is invalid.", runtime.Rlimits[index])
		}
	}

	for index := 0; index < len(runtime.Namespaces); index++ {
		if !namespaceValid(runtime.Namespaces[index]) {
			logrus.Fatalf("Namespace %s is invalid.", runtime.Namespaces[index])
		}
	}

	//minimum devices
	devices := requiredDevices()
	for index := 0; index < len(devices); index++ {
		found := false
		for dIndex := 0; dIndex < len(runtime.Devices); dIndex++ {
			if runtime.Devices[dIndex].Path == devices[index] {
				found = true
				break
			}
		}
		if found == false {
			logrus.Fatalf("Required device %s is missing.", devices[index])
		}
	}

	for index := 0; index < len(runtime.Devices); index++ {
		if !deviceValid(runtime.Devices[index]) {
			logrus.Fatalf("Device %s is invalid.", runtime.Devices[index].Path)
		}
	}

	if len(runtime.ApparmorProfile) > 0 {
		profilePath := path.Join(rootfs, "/etc/apparmor.d", runtime.ApparmorProfile)
		_, err := os.Stat(profilePath)
		if err != nil {
			logrus.Fatal(err)
		}
	}

	switch runtime.RootfsPropagation {
	case "":
	case "private":
	case "rprivate":
	case "slave":
	case "rslave":
	case "shared":
	case "rshared":
	default:
		logrus.Fatalf("rootfs-propagation must be empty or one of private|rprivate|slave|rslave|shared|rshared")
	}

	//TODO: After using protobuf, it will become a 'pointer' so check only if the pointer is valid
	CheckSeccomp(runtime.Seccomp)
}

func CheckSeccomp(s specs.Seccomp) {
	if !seccompActionValid(s.DefaultAction) {
		logrus.Fatalf("Seccomp.DefaultAction is invalid.")
	}
	for index := 0; index < len(s.Syscalls); index++ {
		if s.Syscalls[index] != nil {
			if !syscallValid(*(s.Syscalls[index])) {
				logrus.Fatalf("Syscall action is invalid.")
			}
		}
	}
	for index := 0; index < len(s.Architectures); index++ {
		switch s.Architectures[index] {
		case specs.ArchX86:
		case specs.ArchX86_64:
		case specs.ArchX32:
		case specs.ArchARM:
		case specs.ArchAARCH64:
		case specs.ArchMIPS:
		case specs.ArchMIPS64:
		case specs.ArchMIPS64N32:
		case specs.ArchMIPSEL:
		case specs.ArchMIPSEL64:
		case specs.ArchMIPSEL64N32:
		default:
			logrus.Fatalf("Seccomp.Architecture [%s] is invalid", s.Architectures[index])
		}
	}
}

func requiredPaths() []string {
	paths := []string{
		"/proc",
		"/sys",
	}
	return paths
}

func requiredDevices() []string {
	devices := []string{
		"/dev/null",
		"/dev/zero",
		"/dev/full",
		"/dev/random",
		"/dev/urandom",
		"/dev/tty",
		"/dev/console",
	}
	return devices
}

func capValid(capability string) bool {
	caps := map[string]int{
		"CAP_CHOWN":            0,
		"CAP_DAC_OVERRIDE":     1,
		"CAP_DAC_READ_SEARCH":  2,
		"CAP_FOWNER":           3,
		"CAP_FSETID":           4,
		"CAP_KILL":             5,
		"CAP_SETGID":           6,
		"CAP_SETUID":           7,
		"CAP_SETPCAP":          8,
		"CAP_LINUX_IMMUTABLE":  9,
		"CAP_NET_BIND_SERVICE": 10,
		"CAP_NET_BROADCAST":    11,
		"CAP_NET_ADMIN":        12,
		"CAP_NET_RAW":          13,
		"CAP_IPC_LOCK":         14,
		"CAP_IPC_OWNER":        15,
		"CAP_SYS_MODULE":       16,
		"CAP_SYS_RAWIO":        17,
		"CAP_SYS_CHROOT":       18,
		"CAP_SYS_PTRACE":       19,
		"CAP_SYS_PACCT":        20,
		"CAP_SYS_ADMIN":        21,
		"CAP_SYS_BOOT":         22,
		"CAP_SYS_NICE":         23,
		"CAP_SYS_RESOURCE":     24,
		"CAP_SYS_TIME":         25,
		"CAP_SYS_TTY_CONFIG":   26,
		"CAP_MKNOD":            27,
		"CAP_LEASE":            28,
		"CAP_AUDIT_WRITE":      29,
		"CAP_AUDIT_CONTROL":    30,
		"CAP_SETFCAP":          31,
		"CAP_MAC_OVERRIDE":     32,
		"CAP_MAC_ADMIN":        33,
		"CAP_SYSLOG":           34,
		"CAP_WAKE_ALARM":       35,
		"CAP_BLOCK_SUSPEND":    36,
	}
	_, ok := caps[capability]
	return ok
}

func rlimitValid(rlimit string) bool {
	rlimits := map[string]int{
		"RLIMIT_CPU":        0,
		"RLIMIT_FSIZE":      1,
		"RLIMIT_DATA":       2,
		"RLIMIT_STACK":      3,
		"RLIMIT_CORE":       4,
		"RLIMIT_RSS":        5,
		"RLIMIT_NPROC":      6,
		"RLIMIT_NOFILE":     7,
		"RLIMIT_MEMLOCK":    8,
		"RLIMIT_AS":         9,
		"RLIMIT_LOCKS":      10,
		"RLIMIT_SIGPENDING": 11,
		"RLIMIT_MSGQUEUE":   12,
		"RLIMIT_NICE":       13,
		"RLIMIT_RTPRIO":     14,
		"RLIMIT_RTTIME":     15,
	}
	_, ok := rlimits[rlimit]
	return ok
}

func namespaceValid(ns specs.Namespace) bool {
	switch ns.Type {
	case specs.PIDNamespace:
	case specs.NetworkNamespace:
	case specs.MountNamespace:
	case specs.IPCNamespace:
	case specs.UTSNamespace:
	case specs.UserNamespace:
	default:
		return false
	}
	return true
}

func deviceValid(d specs.Device) bool {
	switch d.Type {
	case 'b':
	case 'c':
	case 'u':
		if d.Major <= 0 {
			return false
		}
		if d.Minor <= 0 {
			return false
		}
	case 'p':
		if d.Major > 0 || d.Minor > 0 {
			return false
		}
	default:
		return false
	}
	return true
}

func seccompActionValid(secc specs.Action) bool {
	switch secc {
	case specs.ActKill:
	case specs.ActTrap:
	case specs.ActErrno:
	case specs.ActTrace:
	case specs.ActAllow:
	default:
		return false
	}
	return true
}

func syscallValid(s specs.Syscall) bool {
	if !seccompActionValid(s.Action) {
		return false
	}
	for index := 0; index < len(s.Args); index++ {
		arg := *(s.Args[index])
		switch arg.Op {
		case specs.OpNotEqual:
		case specs.OpLessEqual:
		case specs.OpEqualTo:
		case specs.OpGreaterEqual:
		case specs.OpGreaterThan:
		case specs.OpMaskedEqual:
		default:
			return false
		}
	}
	return true
}
