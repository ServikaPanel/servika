package system

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// kcAnswers scripts the agent: each subcommand answers with its output and exit
// code, and one that is not listed exits 1 with nothing.
func kcAnswers(t *testing.T, installed, running bool, answers map[string]string) {
	t.Helper()
	setForTest(t, &kcInstalled, func() bool { return installed })
	setForTest(t, &kcRunning, func() bool { return running })
	setForTest(t, &kcShell, func(_ time.Duration, args ...string) (string, int) {
		out, answered := answers[args[0]]
		if !answered {
			return "", 1
		}
		return out, 0
	})
}

// A host without the agent says so and asks it nothing: the whole layer is
// silent when kcarectl is absent.
func TestKernelcareStatusIsSilentWithoutTheAgent(t *testing.T) {
	asked := false
	setForTest(t, &kcInstalled, func() bool { return false })
	setForTest(t, &kcShell, func(_ time.Duration, _ ...string) (string, int) {
		asked = true
		return "", 0
	})

	if kc := kernelcareStatus(); !reflect.DeepEqual(kc, KcStatus{}) {
		t.Fatalf("status = %+v, want the zero value", kc)
	}
	if asked {
		t.Error("the agent was called on a host that does not have it")
	}
}

// The patched kernel, the live patches and the registration each come from
// their own command, and a command that fails leaves its field alone.
func TestKernelcareStatusReadsEachFieldFromItsOwnCommand(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		answers map[string]string
		want    KcStatus
	}{
		{name: "an agent that answers nothing", answers: map[string]string{},
			want: KcStatus{Installed: true}},
		{name: "a patched kernel with no patches loaded",
			answers: map[string]string{"--uname": "6.12.0-55.9.1.el10_0.x86_64\n"},
			want:    KcStatus{Installed: true, EffectiveKernel: "6.12.0-55.9.1.el10_0.x86_64"}},
		{name: "patches loaded",
			answers: map[string]string{"--patch-info": "kpatch CVE-2025-0001, CVE-2025-0002; (CVE-2025-0001)"},
			want: KcStatus{Installed: true, Active: true,
				PatchedCves: []string{"CVE-2025-0001", "CVE-2025-0002"}}},
		{name: "an empty patch report",
			answers: map[string]string{"--patch-info": "   \n"},
			want:    KcStatus{Installed: true}},
		{name: "a registered agent",
			answers: map[string]string{"--info": "key: ABCD1234\nstatus: ok"},
			want:    KcStatus{Installed: true, Registered: true}},
		{name: "an agent that is not registered",
			answers: map[string]string{"--info": "Server is UNREGISTERED"},
			want:    KcStatus{Installed: true}},
		{name: "an agent with no key",
			answers: map[string]string{"--info": "No valid key found"},
			want:    KcStatus{Installed: true}},
		{name: "an update in progress", running: true, answers: map[string]string{},
			want: KcStatus{Installed: true, Running: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kcAnswers(t, true, tc.running, tc.answers)
			if kc := kernelcareStatus(); !reflect.DeepEqual(kc, tc.want) {
				t.Errorf("status = %+v, want %+v", kc, tc.want)
			}
		})
	}
}

// The CVE list comes out of free-form agent output, so the separators it uses
// and the repeats it prints both have to be handled.
func TestKernelcareStatusListsEachPatchedCveOnce(t *testing.T) {
	kcAnswers(t, true, false, map[string]string{
		"--patch-info": strings.Join([]string{
			"kpatch-name: kernel-6.12",
			"cves: CVE-2025-0001,CVE-2025-0002 (CVE-2025-0003)",
			"also CVE-2025-0002;CVE-2025-0004",
		}, "\n"),
	})

	kc := kernelcareStatus()
	want := []string{"CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003", "CVE-2025-0004"}
	if !reflect.DeepEqual(kc.PatchedCves, want) {
		t.Errorf("patched = %v, want %v", kc.PatchedCves, want)
	}
}
