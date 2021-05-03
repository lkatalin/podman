package seccomp

import (
	"sort"

	"github.com/pkg/errors"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
)

// ContainerImageLabel is the key of the image annotation embedding a seccomp
// profile.
const ContainerImageLabel = "io.containers.seccomp.profile"

// Policy denotes a seccomp policy.
type Policy int

const (
	// PolicyDefault - if set use SecurityConfig.SeccompProfilePath,
	// otherwise use the default profile.  The SeccompProfilePath might be
	// explicitly set by the user.
	PolicyDefault Policy = iota
	// PolicyImage - if set use SecurityConfig.SeccompProfileFromImage,
	// otherwise follow SeccompPolicyDefault.
	PolicyImage
)

// Map for easy lookups of supported policies.
var supportedPolicies = map[string]Policy{
	"":        PolicyDefault,
	"default": PolicyDefault,
	"image":   PolicyImage,
}

// LookupPolicy looks up the corresponding Policy for the specified
// string. If none is found, an errors is returned including the list of
// supported policies.
//
// Note that an empty string resolved to SeccompPolicyDefault.
func LookupPolicy(s string) (Policy, error) {
	policy, exists := supportedPolicies[s]
	if exists {
		return policy, nil
	}

	// Sort the keys first as maps are non-deterministic.
	keys := []string{}
	for k := range supportedPolicies {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	return -1, errors.Errorf("invalid seccomp policy %q: valid policies are %+q", s, keys)
}

// This function compares the seccomp profile of an image against a default
// seccomp profile and returns the image profile iff it is a strict subset of
// the default profile. A strict subset means:
// 1. Any syscalls allowed by the image profile must also be allowed in the default
//    with the same parameters.
// 2. The default profile includes more syscalls than the image profile.
func compare(dflt specs.LinuxSeccomp, img specs.LinuxSeccomp) specs.LinuxSeccomp {
        // Create mapping of syscalls -> rules from both profiles.
        var defaultProfile = make(map[string]specs.LinuxSyscall)
        var imgProfile = make (map[string]specs.LinuxSyscall)
        for _, rule := range dflt.Syscalls {
                for _, name := range rule.Names {
                        defaultProfile[name] = rule
                }
        }
        for _, rule := range img.Syscalls {
                for _, name := range rule.Names {
                        imgProfile[name] = rule
                }
        }

        // Check whether set of syscalls in default is larger than the set in img;
        // if not, it won't be a strict subset, so return default.
        var allPresent = true
        for syscall := range defaultProfile {
                _, ok := imgProfile[syscall]
                if !ok {
                        allPresent = false
                }
        }
        if allPresent {
                logrus.Debugf("img seccomp profile is not strict subset; returning default")
                return dflt
        }

        // Check that all rules for img syscalls are the same ones present in the
        // default profile for that syscall.
        for syscall, imgRule := range imgProfile {
                defaultRule := defaultProfile[syscall]
                // TODO: better iterator over fields?
                if (!cmp.Equal(defaultRule.Action, imgRule.Action) ||
                    !cmp.Equal(defaultRule.ErrnoRet, imgRule.ErrnoRet) ||
                    !cmp.Equal(defaultRule.Args, imgRule.Args)) {
                     logrus.Debugf("default rule %v not equal to img rule %v for syscall %v; returning default profile\n", defaultRule.Action, imgRule.Action, syscall)
                        return dflt
                }
        }

        logrus.Debugf("img seccomp profile is stricter than default; returning img profile")
        return img
}
