package enrollment_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This consumer has its own module and runs outside the checkout. The replace
// selects the candidate source at build time, not a runtime asset directory.
func TestIndependentModuleCanGenerateOffline(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/consumer\n\ngo 1.26.0\n\nrequire github.com/egress-gateway/egress-gateway-networking v0.0.0\n\nreplace github.com/egress-gateway/egress-gateway-networking => " + root + "\n",
		"main.go": `package main
import (
 "encoding/json"
 "os"
 "github.com/egress-gateway/egress-gateway-networking/baseline"
 "github.com/egress-gateway/egress-gateway-networking/enrollment"
 core "k8s.io/api/core/v1"
 meta "k8s.io/apimachinery/pkg/apis/meta/v1"
 "k8s.io/apimachinery/pkg/util/intstr"
)
func main() {
 n := enrollment.Network{Namespace:"tenant", Binding:"bound", Control: &enrollment.Istiod{IPv4:"10.96.0.12", Hostname:"istiod.istio-system.svc", Peer:enrollment.Peer{Namespace:"istio-system",PodLabels:map[string]string{"app":"istiod"}}}}
 policy, err := enrollment.ExpandPolicy(n); if err != nil {panic(err)}
 security := func(id int64)*core.SecurityContext {return &core.SecurityContext{RunAsUser:new(id),RunAsGroup:new(id),AllowPrivilegeEscalation:new(false),Capabilities:&core.Capabilities{Drop:[]core.Capability{"ALL"}}}}
 probe := &core.Probe{ProbeHandler:core.ProbeHandler{HTTPGet:&core.HTTPGetAction{Path:"/healthz/ready",Port:intstr.FromInt32(15021)}}}
 p := &core.Pod{ObjectMeta:meta.ObjectMeta{Namespace:"tenant",GenerateName:"agent-",Labels:map[string]string{"example.test/enabled":"true"}}, Spec:core.PodSpec{ServiceAccountName:"agent",Containers:[]core.Container{{Name:"app",Image:"example/app",SecurityContext:security(10000)}},InitContainers:[]core.Container{{Name:enrollment.ProxyName,Image:baseline.Current().Runtime["ISTIO_PROXY_IMAGE"],RestartPolicy:new(core.ContainerRestartPolicyAlways),StartupProbe:probe,ReadinessProbe:probe,SecurityContext:security(1337)}}}}
 pod, err := enrollment.ExpandPod(p,enrollment.Options{Network:n,EnabledLabel:"example.test/enabled"}); if err != nil {panic(err)}
 if pod.Labels[enrollment.BindingLabel] != policy.Labels[enrollment.BindingLabel] {panic("binding mismatch")}
 if err = json.NewEncoder(os.Stdout).Encode(pod); err != nil {panic(err)}
}
`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-mod=mod", "-o", filepath.Join(dir, "consumer"), ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external build: %v\n%s", err, out)
	}
	empty := t.TempDir()
	cmd = exec.CommandContext(t.Context(), filepath.Join(dir, "consumer"))
	cmd.Dir = empty
	cmd.Env = []string{"HOME=" + empty, "KUBECONFIG=" + filepath.Join(empty, "missing")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline generation: %v\n%s", err, out)
	}
}
