/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package netpol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/kubernetes/test/e2e/storage/utils"

	"github.com/onsi/ginkgo"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	"k8s.io/kubernetes/test/e2e/network/common"
	imageutils "k8s.io/kubernetes/test/utils/image"
	admissionapi "k8s.io/pod-security-admission/api"
)

/*
The following Network Policy tests verify that policy object definitions
are correctly enforced by a networking plugin. It accomplishes this by launching
a simple netcat server, and two clients with different
attributes. Each test case creates a network policy which should only allow
connections from one of the clients. The test then asserts that the clients
failed or successfully connected as expected.
*/

type protocolPort struct {
	port     int
	protocol v1.Protocol
}

var _ = common.SIGDescribe("NetworkPolicy [Feature:SCTPConnectivity][LinuxOnly][Disruptive]", func() {
	var service *v1.Service
	var podServer *v1.Pod
	var podServerLabelSelector string
	f := framework.NewDefaultFramework("sctp-network-policy")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	ginkgo.BeforeEach(func() {
		// Windows does not support network policies.
		e2eskipper.SkipIfNodeOSDistroIs("windows")
	})

	ginkgo.Context("NetworkPolicy between server and client using SCTP", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Creating a simple server that serves on port 80 and 81.")
			podServer, service = createServerPodAndService(f, f.Namespace, "server", []protocolPort{{80, v1.ProtocolSCTP}, {81, v1.ProtocolSCTP}})

			ginkgo.By("Waiting for pod ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podServer.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err)
			})

			// podServerLabelSelector holds the value for the podServer's label "pod-name".
			podServerLabelSelector = podServer.ObjectMeta.Labels["pod-name"]

			// Create pods, which should be able to communicate with the server on port 80 and 81.
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			testCanConnectProtocol(f, f.Namespace, "client-can-connect-80", service, 80, v1.ProtocolSCTP)
			testCanConnectProtocol(f, f.Namespace, "client-can-connect-81", service, 81, v1.ProtocolSCTP)
		})

		ginkgo.AfterEach(func() {
			cleanupServerPodAndService(f, podServer, service)
		})

		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{},
				},
			}

			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policy, metav1.CreateOptions{})
			framework.ExpectNoError(err)
			defer cleanupNetworkPolicy(f, policy)

			// Create a pod with name 'client-cannot-connect', which will attempt to communicate with the server,
			// but should not be able to now that isolation is on.
			testCannotConnect(f, f.Namespace, "client-cannot-connect", service, 80)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the Service which allows traffic only to one port.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-on-port-81",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply to server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServerLabelSelector,
						},
					},
					// Allow traffic only to one port.
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Port:     &intstr.IntOrString{IntVal: 81},
							Protocol: &protocolSCTP,
						}},
					}},
				},
			}
			policy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policy, metav1.CreateOptions{})
			framework.ExpectNoError(err)
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Testing pods can connect only to the port allowed by the policy.")
			testCannotConnectProtocol(f, f.Namespace, "client-a", service, 80, v1.ProtocolSCTP)
			testCanConnectProtocol(f, f.Namespace, "client-b", service, 81, v1.ProtocolSCTP)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			nsA := f.Namespace
			nsBName := f.BaseName + "-b"
			nsB, err := f.CreateNamespace(nsBName, map[string]string{
				"ns-name": nsBName,
			})
			framework.ExpectNoError(err, "Error occurred while creating namespace-b.")

			// Wait for Server in namespaces-a to be ready
			framework.Logf("Waiting for server to come up.")
			err = e2epod.WaitForPodRunningInNamespace(f.ClientSet, podServer)
			framework.ExpectNoError(err, "Error occurred while waiting for pod status in namespace: Running.")

			// Before application of the policy, all communication should be successful.
			ginkgo.By("Creating client-a, in server's namespace, which should be able to contact the server.", func() {
				testCanConnectProtocol(f, nsA, "client-a", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-b, in server's namespace, which should be able to contact the server.", func() {
				testCanConnectProtocol(f, nsA, "client-b", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-a, not in server's namespace, which should be able to contact the server.", func() {
				testCanConnectProtocol(f, nsB, "client-a", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-b, not in server's namespace, which should be able to contact the server.", func() {
				testCanConnectProtocol(f, nsB, "client-b", service, 80, v1.ProtocolSCTP)
			})

			ginkgo.By("Creating a network policy for the server which allows traffic only from client-a in namespace-b.")
			policy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: nsA.Name,
					Name:      "allow-ns-b-client-a-via-namespace-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServerLabelSelector,
						},
					},
					// Allow traffic only from client-a in namespace-b
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"ns-name": nsBName,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod-name": "client-a",
								},
							},
						}},
					}},
				},
			}

			policy, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policy, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policy.")
			defer cleanupNetworkPolicy(f, policy)

			ginkgo.By("Creating client-a, in server's namespace, which should not be able to contact the server.", func() {
				testCannotConnectProtocol(f, nsA, "client-a", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-b, in server's namespace, which should not be able to contact the server.", func() {
				testCannotConnectProtocol(f, nsA, "client-b", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-a, not in server's namespace, which should be able to contact the server.", func() {
				testCanConnectProtocol(f, nsB, "client-a", service, 80, v1.ProtocolSCTP)
			})
			ginkgo.By("Creating client-b, not in server's namespace, which should not be able to contact the server.", func() {
				testCannotConnectProtocol(f, nsB, "client-b", service, 80, v1.ProtocolSCTP)
			})
		})
	})
})

func testCanConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	testCanConnectProtocol(f, ns, podName, service, targetPort, v1.ProtocolTCP)
}

func testCannotConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	testCannotConnectProtocol(f, ns, podName, service, targetPort, v1.ProtocolTCP)
}

func testCanConnectProtocol(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int, protocol v1.Protocol) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should successfully connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort, protocol)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podClient.Name))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(context.TODO(), podClient.Name, metav1.DeleteOptions{}); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()
	checkConnectivity(f, ns, podClient, service)
}

func testCannotConnectProtocol(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int, protocol v1.Protocol) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should not be able to connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort, protocol)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podClient.Name))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(context.TODO(), podClient.Name, metav1.DeleteOptions{}); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()

	checkNoConnectivity(f, ns, podClient, service)
}

func checkConnectivity(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err := e2epod.WaitForPodNoLongerRunningInNamespace(f.ClientSet, podClient.Name, ns.Name)
	framework.ExpectNoError(err, "Pod did not finish as expected.")

	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err = e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)
	if err != nil {
		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)

		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should be able to connect to service %s, but was not able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

	}
}

func checkNoConnectivity(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err := e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)

	// We expect an error here since it's a cannot connect test.
	// Dump debug information if the error was nil.
	if err == nil {
		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)

		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should not be able to connect to service %s, but was able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t %v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

	}
}

func checkNoConnectivityByExitCode(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	err := e2epod.WaitForPodCondition(f.ClientSet, ns.Name, podClient.Name, "terminated", framework.PodStartTimeout, func(pod *v1.Pod) (bool, error) {
		statuses := pod.Status.ContainerStatuses
		if len(statuses) == 0 || statuses[0].State.Terminated == nil {
			return false, nil
		}
		if statuses[0].State.Terminated.ExitCode != 0 {
			return true, fmt.Errorf("pod %q container exited with code: %d", podClient.Name, statuses[0].State.Terminated.ExitCode)
		}
		return true, nil
	})
	// We expect an error here since it's a cannot connect test.
	// Dump debug information if the error was nil.
	if err == nil {
		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should not be able to connect to service %s, but was able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func collectPodsAndNetworkPolicies(f *framework.Framework, podClient *v1.Pod) ([]string, *networkingv1.NetworkPolicyList, string) {
	// Collect pod logs when we see a failure.
	logs, logErr := e2epod.GetPodLogs(f.ClientSet, f.Namespace.Name, podClient.Name, "client")
	if logErr != nil && apierrors.IsNotFound(logErr) {
		// Pod may have already been removed; try to get previous pod logs
		logs, logErr = e2epod.GetPreviousPodLogs(f.ClientSet, f.Namespace.Name, podClient.Name, fmt.Sprintf("%s-container", podClient.Name))
	}
	if logErr != nil {
		framework.Logf("Error getting container logs: %s", logErr)
	}

	// Collect current NetworkPolicies applied in the test namespace.
	policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		framework.Logf("error getting current NetworkPolicies for %s namespace: %s", f.Namespace.Name, err)
	}
	// Collect the list of pods running in the test namespace.
	podsInNS, err := e2epod.GetPodsInNamespace(f.ClientSet, f.Namespace.Name, map[string]string{})
	if err != nil {
		framework.Logf("error getting pods for %s namespace: %s", f.Namespace.Name, err)
	}
	pods := []string{}
	for _, p := range podsInNS {
		pods = append(pods, fmt.Sprintf("Pod: %s, Status: %s\n", p.Name, p.Status.String()))
	}
	return pods, policies, logs
}

// Create a server pod with a listening container for each port in ports[].
// Will also assign a pod label with key: "pod-name" and label set to the given podName for later use by the network
// policy.
func createServerPodAndService(f *framework.Framework, namespace *v1.Namespace, podName string, ports []protocolPort) (*v1.Pod, *v1.Service) {
	// Because we have a variable amount of ports, we'll first loop through and generate our Containers for our pod,
	// and ServicePorts.for our Service.
	containers := []v1.Container{}
	servicePorts := []v1.ServicePort{}
	for _, portProtocol := range ports {
		var porterPort string
		var connectProtocol string
		switch portProtocol.protocol {
		case v1.ProtocolTCP:
			porterPort = fmt.Sprintf("SERVE_PORT_%d", portProtocol.port)
			connectProtocol = "tcp"
		case v1.ProtocolSCTP:
			porterPort = fmt.Sprintf("SERVE_SCTP_PORT_%d", portProtocol.port)
			connectProtocol = "sctp"
		default:
			framework.Failf("createServerPodAndService, unexpected protocol %v", portProtocol.protocol)
		}

		containers = append(containers, v1.Container{
			Name:  fmt.Sprintf("%s-container-%d", podName, portProtocol.port),
			Image: imageutils.GetE2EImage(imageutils.Agnhost),
			Args:  []string{"porter"},
			Env: []v1.EnvVar{
				{
					Name:  porterPort,
					Value: "foo",
				},
			},
			Ports: []v1.ContainerPort{
				{
					ContainerPort: int32(portProtocol.port),
					Name:          fmt.Sprintf("serve-%d", portProtocol.port),
					Protocol:      portProtocol.protocol,
				},
			},
			ReadinessProbe: &v1.Probe{
				ProbeHandler: v1.ProbeHandler{
					Exec: &v1.ExecAction{
						Command: []string{"/agnhost", "connect", fmt.Sprintf("--protocol=%s", connectProtocol), "--timeout=1s", fmt.Sprintf("127.0.0.1:%d", portProtocol.port)},
					},
				},
			},
		})

		// Build the Service Ports for the service.
		servicePorts = append(servicePorts, v1.ServicePort{
			Name:       fmt.Sprintf("%s-%d", podName, portProtocol.port),
			Port:       int32(portProtocol.port),
			TargetPort: intstr.FromInt(portProtocol.port),
			Protocol:   portProtocol.protocol,
		})
	}

	ginkgo.By(fmt.Sprintf("Creating a server pod %s in namespace %s", podName, namespace.Name))
	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podName + "-",
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			Containers:    containers,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	framework.Logf("Created pod %v", pod.ObjectMeta.Name)

	svcName := fmt.Sprintf("svc-%s", podName)
	ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", svcName, podName, namespace.Name))
	svc, err := f.ClientSet.CoreV1().Services(namespace.Name).Create(context.TODO(), &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: v1.ServiceSpec{
			Ports: servicePorts,
			Selector: map[string]string{
				"pod-name": podName,
			},
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	framework.Logf("Created service %s", svc.Name)

	return pod, svc
}

func cleanupServerPodAndService(f *framework.Framework, pod *v1.Pod, service *v1.Service) {
	ginkgo.By("Cleaning up the server.")
	if err := f.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup pod %v: %v", pod.Name, err)
	}
	ginkgo.By("Cleaning up the server's service.")
	if err := f.ClientSet.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup svc %v: %v", service.Name, err)
	}
}

// Create a client pod which will attempt a netcat to the provided service, on the specified port.
// This client will attempt a one-shot connection, then die, without restarting the pod.
// Test can then be asserted based on whether the pod quit with an error or not.
func createNetworkClientPod(f *framework.Framework, namespace *v1.Namespace, podName string, targetService *v1.Service, targetPort int, protocol v1.Protocol) *v1.Pod {
	return createNetworkClientPodWithRestartPolicy(f, namespace, podName, targetService, targetPort, protocol, v1.RestartPolicyNever)
}

// Create a client pod which will attempt a netcat to the provided service, on the specified port.
// It is similar to createNetworkClientPod but supports specifying RestartPolicy.
func createNetworkClientPodWithRestartPolicy(f *framework.Framework, namespace *v1.Namespace, podName string, targetService *v1.Service, targetPort int, protocol v1.Protocol, restartPolicy v1.RestartPolicy) *v1.Pod {
	var connectProtocol string
	switch protocol {
	case v1.ProtocolTCP:
		connectProtocol = "tcp"
	case v1.ProtocolSCTP:
		connectProtocol = "sctp"
	default:
		framework.Failf("createNetworkClientPodWithRestartPolicy, unexpected protocol %v", protocol)
	}

	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podName + "-",
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			RestartPolicy: restartPolicy,
			Containers: []v1.Container{
				{
					Name:    "client",
					Image:   imageutils.GetE2EImage(imageutils.Agnhost),
					Command: []string{"/bin/sh"},
					Args: []string{
						"-c",
						fmt.Sprintf("for i in $(seq 1 5); do /agnhost connect %s --protocol %s --timeout 8s && exit 0 || sleep 1; done; exit 1", net.JoinHostPort(targetService.Spec.ClusterIP, strconv.Itoa(targetPort)), connectProtocol),
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	return pod
}

// Patch pod with a map value
func updatePodLabel(f *framework.Framework, namespace *v1.Namespace, podName string, patchOperation string, patchPath string, patchValue map[string]string) *v1.Pod {
	type patchMapValue struct {
		Op    string            `json:"op"`
		Path  string            `json:"path"`
		Value map[string]string `json:"value,omitempty"`
	}
	payload := []patchMapValue{{
		Op:    patchOperation,
		Path:  patchPath,
		Value: patchValue,
	}}
	payloadBytes, err := json.Marshal(payload)
	framework.ExpectNoError(err)

	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Patch(context.TODO(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	framework.ExpectNoError(err)

	return pod
}

func cleanupNetworkPolicy(f *framework.Framework, policy *networkingv1.NetworkPolicy) {
	ginkgo.By("Cleaning up the policy.")
	if err := f.ClientSet.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup policy %v: %v", policy.Name, err)
	}
}

var _ = common.SIGDescribe("NetworkPolicy API", func() {
	f := framework.NewDefaultFramework("networkpolicies")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged
	/*
		Release: v1.20
		Testname: NetworkPolicies API
		Description:
		- The networking.k8s.io API group MUST exist in the /apis discovery document.
		- The networking.k8s.io/v1 API group/version MUST exist in the /apis/networking.k8s.io discovery document.
		- The NetworkPolicies resources MUST exist in the /apis/networking.k8s.io/v1 discovery document.
		- The NetworkPolicies resource must support create, get, list, watch, update, patch, delete, and deletecollection.
	*/

	ginkgo.It("should support creating NetworkPolicy API operations", func() {
		// Setup
		ns := f.Namespace.Name
		npVersion := "v1"
		npClient := f.ClientSet.NetworkingV1().NetworkPolicies(ns)
		npTemplate := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "e2e-example-netpol",
				Labels: map[string]string{
					"special-label": f.UniqueName,
				},
			},
			Spec: networkingv1.NetworkPolicySpec{
				// Apply this policy to the Server
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod-name": "test-pod",
					},
				},
				// Allow traffic only from client-a in namespace-b
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"ns-name": "pod-b",
							},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"pod-name": "client-a",
							},
						},
					}},
				}},
			},
		}
		// Discovery
		ginkgo.By("getting /apis")
		{
			discoveryGroups, err := f.ClientSet.Discovery().ServerGroups()
			framework.ExpectNoError(err)
			found := false
			for _, group := range discoveryGroups.Groups {
				if group.Name == networkingv1.GroupName {
					for _, version := range group.Versions {
						if version.Version == npVersion {
							found = true
							break
						}
					}
				}
			}
			if !found {
				framework.Failf("expected networking API group/version, got %#v", discoveryGroups.Groups)
			}
		}
		ginkgo.By("getting /apis/networking.k8s.io")
		{
			group := &metav1.APIGroup{}
			err := f.ClientSet.Discovery().RESTClient().Get().AbsPath("/apis/networking.k8s.io").Do(context.TODO()).Into(group)
			framework.ExpectNoError(err)
			found := false
			for _, version := range group.Versions {
				if version.Version == npVersion {
					found = true
					break
				}
			}
			if !found {
				framework.Failf("expected networking API version, got %#v", group.Versions)
			}
		}
		ginkgo.By("getting /apis/networking.k8s.io" + npVersion)
		{
			resources, err := f.ClientSet.Discovery().ServerResourcesForGroupVersion(networkingv1.SchemeGroupVersion.String())
			framework.ExpectNoError(err)
			foundNetPol := false
			for _, resource := range resources.APIResources {
				switch resource.Name {
				case "networkpolicies":
					foundNetPol = true
				}
			}
			if !foundNetPol {
				framework.Failf("expected networkpolicies, got %#v", resources.APIResources)
			}
		}
		// NetPol resource create/read/update/watch verbs
		ginkgo.By("creating")
		_, err := npClient.Create(context.TODO(), npTemplate, metav1.CreateOptions{})
		framework.ExpectNoError(err)
		_, err = npClient.Create(context.TODO(), npTemplate, metav1.CreateOptions{})
		framework.ExpectNoError(err)
		createdNetPol, err := npClient.Create(context.TODO(), npTemplate, metav1.CreateOptions{})
		framework.ExpectNoError(err)

		ginkgo.By("getting")
		gottenNetPol, err := npClient.Get(context.TODO(), createdNetPol.Name, metav1.GetOptions{})
		framework.ExpectNoError(err)
		framework.ExpectEqual(gottenNetPol.UID, createdNetPol.UID)

		ginkgo.By("listing")
		nps, err := npClient.List(context.TODO(), metav1.ListOptions{LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		framework.ExpectEqual(len(nps.Items), 3, "filtered list should have 3 items")

		ginkgo.By("watching")
		framework.Logf("starting watch")
		npWatch, err := npClient.Watch(context.TODO(), metav1.ListOptions{ResourceVersion: nps.ResourceVersion, LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		// Test cluster-wide list and watch
		clusterNPClient := f.ClientSet.NetworkingV1().NetworkPolicies("")
		ginkgo.By("cluster-wide listing")
		clusterNPs, err := clusterNPClient.List(context.TODO(), metav1.ListOptions{LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		framework.ExpectEqual(len(clusterNPs.Items), 3, "filtered list should have 3 items")

		ginkgo.By("cluster-wide watching")
		framework.Logf("starting watch")
		_, err = clusterNPClient.Watch(context.TODO(), metav1.ListOptions{ResourceVersion: nps.ResourceVersion, LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)

		ginkgo.By("patching")
		patchedNetPols, err := npClient.Patch(context.TODO(), createdNetPol.Name, types.MergePatchType, []byte(`{"metadata":{"annotations":{"patched":"true"}}}`), metav1.PatchOptions{})
		framework.ExpectNoError(err)
		framework.ExpectEqual(patchedNetPols.Annotations["patched"], "true", "patched object should have the applied annotation")

		ginkgo.By("updating")
		npToUpdate := patchedNetPols.DeepCopy()
		npToUpdate.Annotations["updated"] = "true"
		updatedNetPols, err := npClient.Update(context.TODO(), npToUpdate, metav1.UpdateOptions{})
		framework.ExpectNoError(err)
		framework.ExpectEqual(updatedNetPols.Annotations["updated"], "true", "updated object should have the applied annotation")

		framework.Logf("waiting for watch events with expected annotations")
		for sawAnnotations := false; !sawAnnotations; {
			select {
			case evt, ok := <-npWatch.ResultChan():
				if !ok {
					framework.Fail("watch channel should not close")
				}
				framework.ExpectEqual(evt.Type, watch.Modified)
				watchedNetPol, isNetPol := evt.Object.(*networkingv1.NetworkPolicy)
				if !isNetPol {
					framework.Failf("expected NetworkPolicy, got %T", evt.Object)
				}
				if watchedNetPol.Annotations["patched"] == "true" && watchedNetPol.Annotations["updated"] == "true" {
					framework.Logf("saw patched and updated annotations")
					sawAnnotations = true
					npWatch.Stop()
				} else {
					framework.Logf("missing expected annotations, waiting: %#v", watchedNetPol.Annotations)
				}
			case <-time.After(wait.ForeverTestTimeout):
				framework.Fail("timed out waiting for watch event")
			}
		}
		// NetPol resource delete operations
		ginkgo.By("deleting")
		err = npClient.Delete(context.TODO(), createdNetPol.Name, metav1.DeleteOptions{})
		framework.ExpectNoError(err)
		_, err = npClient.Get(context.TODO(), createdNetPol.Name, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			framework.Failf("expected 404, got %#v", err)
		}
		nps, err = npClient.List(context.TODO(), metav1.ListOptions{LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		framework.ExpectEqual(len(nps.Items), 2, "filtered list should have 2 items")

		ginkgo.By("deleting a collection")
		err = npClient.DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		nps, err = npClient.List(context.TODO(), metav1.ListOptions{LabelSelector: "special-label=" + f.UniqueName})
		framework.ExpectNoError(err)
		framework.ExpectEqual(len(nps.Items), 0, "filtered list should have 0 items")
	})
})

// CheckSCTPModuleLoadedOnNodes checks whether any node on the list has the
// sctp.ko module loaded
// For security reasons, and also to allow clusters to use userspace SCTP implementations,
// we require that just creating an SCTP Pod/Service/NetworkPolicy must not do anything
// that would cause the sctp kernel module to be loaded.
func CheckSCTPModuleLoadedOnNodes(f *framework.Framework, nodes *v1.NodeList) bool {
	hostExec := utils.NewHostExec(f)
	defer hostExec.Cleanup()
	re := regexp.MustCompile(`^\s*sctp\s+`)
	cmd := "lsmod | grep sctp"
	for _, node := range nodes.Items {
		framework.Logf("Executing cmd %q on node %v", cmd, node.Name)
		result, err := hostExec.IssueCommandWithResult(cmd, &node)
		if err != nil {
			framework.Logf("sctp module is not loaded or error occurred while executing command %s on node: %v", cmd, err)
		}
		for _, line := range strings.Split(result, "\n") {
			if found := re.Find([]byte(line)); found != nil {
				framework.Logf("the sctp module is loaded on node: %v", node.Name)
				return true
			}
		}
		framework.Logf("the sctp module is not loaded on node: %v", node.Name)
	}
	return false
}
