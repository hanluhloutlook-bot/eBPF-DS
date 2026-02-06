package com.example;

import com.alibaba.fastjson.JSON;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.AppsV1Api;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1DeploymentSpec;
import io.kubernetes.client.openapi.models.V1LabelSelector;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1PodStatus;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServiceList;
import io.kubernetes.client.openapi.models.V1ServicePort;
import io.kubernetes.client.openapi.models.V1ServiceSpec;
import io.kubernetes.client.custom.IntOrString;
import io.kubernetes.client.util.Config;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NetworkPolicyParser {

    private static String sudoPrefix = "";

    /**
     * 解析本地 input.json 并生成 eBPF 规则写入 map。
     *
     * @param args 启动参数
     */
    public static void main(String[] args) {
        // 检查是否以root用户运行
        if (System.getProperty("user.name").equals("root")) {
            sudoPrefix = "";
        } else {
            sudoPrefix = "sudo ";
        }

        try {
            // Read input JSON file using Fastjson
            byte[] jsonData = Files.readAllBytes(new File("input.json").toPath());
            String jsonString = new String(jsonData);
            NetworkPolicyRequest request = JSON.parseObject(jsonString, NetworkPolicyRequest.class);

            // Configure Kubernetes client
            ApiClient client = Config.defaultClient();
            Configuration.setDefaultApiClient(client);

            // Get target object pods (source for egress, destination for ingress)
            List<String> targetPodIPs = new ArrayList<>();
            List<String> targetServiceIPs = new ArrayList<>();
            String targetNamespace = request.getNamespace();
            TargetObject targetObject = request.getTargetObject();
            if (targetObject.getType().equals("namespace/deployment")) {
                targetPodIPs.addAll(getPodIPsByDeployment(client, targetNamespace, targetObject.getName()));
                targetServiceIPs.addAll(getServiceClusterIPsByDeployment(client, targetNamespace, targetObject.getName()));
            } else if (targetObject.getType().equals("namespace")) {
                if (targetObject.getName() != null && !targetObject.getName().isEmpty()) {
                    targetNamespace = targetObject.getName();
                }
                targetPodIPs.addAll(getPodIPsByNamespace(client, targetNamespace));
                targetServiceIPs.addAll(getServiceClusterIPsByNamespace(client, targetNamespace));
            } else if (targetObject.getType().equals("ips")) {
                targetPodIPs.addAll(parseIpList(targetObject.getName()));
            }

            // 解析白名单/黑名单模式（方向覆盖优先，全局次之）
            String ingressMode = resolveMode(request.getIngressMode(), request.getPolicyMode());
            String egressMode = resolveMode(request.getEgressMode(), request.getPolicyMode());
            boolean ingressWhitelist = isWhitelistMode(ingressMode);
            boolean egressWhitelist = isWhitelistMode(egressMode);

            // 白名单模式下：为目标 Pod 写入管控方向掩码
            if (ingressWhitelist || egressWhitelist) {
                int mask = 0;
                if (ingressWhitelist) {
                    mask |= 1;
                }
                if (egressWhitelist) {
                    mask |= 2;
                }
                List<String> modeTargets = new ArrayList<>(targetPodIPs);
                modeTargets.addAll(targetServiceIPs);
                for (String ip : modeTargets) {
                    if (ip.contains("/")) {
                        continue;
                    }
                    setPolicyMode(ip, mask);
                }
            }

            // Process egress rules
            System.out.println("Egress rules:");
            for (EgressRule egressRule : request.getEgressList()) {
                List<String> destinationIPs = new ArrayList<>();
                Map<String, java.util.Set<Integer>> servicePorts = new HashMap<>();
                if (egressRule.getRemoteType().equals("deployment")) {
                    destinationIPs.addAll(getPodIPsByDeployment(client, egressRule.getRemoteNamespace(), egressRule.getRemoteName()));
                    destinationIPs.addAll(getServiceClusterIPsByDeployment(client, egressRule.getRemoteNamespace(), egressRule.getRemoteName()));
                    servicePorts = getServicePortsByDeployment(client, egressRule.getRemoteNamespace(), egressRule.getRemoteName(), egressRule.getPort());
                } else if (egressRule.getRemoteType().equals("namespace")) {
                    destinationIPs.addAll(getPodIPsByNamespace(client, egressRule.getRemoteNamespace()));
                    destinationIPs.addAll(getServiceClusterIPsByNamespace(client, egressRule.getRemoteNamespace()));
                    servicePorts = getServicePortsByNamespace(client, egressRule.getRemoteNamespace(), egressRule.getPort());
                } else if (egressRule.getRemoteType().equals("ips")) {
                    destinationIPs.addAll(parseIpList(egressRule.getRemoteName()));
                }

                for (String sourceIP : targetPodIPs) {
                    for (String destinationIP : destinationIPs) {
                        String action = egressWhitelist ? "allow" : "drop";
                        System.out.printf("Source IP: %s, Destination IP: %s, Port: %d, Protocol: %s, Policy: %s%n",
                            sourceIP, destinationIP, egressRule.getPort(), egressRule.getProtocol(), action);
                        updateEBPFMap(sourceIP, destinationIP, egressRule.getPort(), egressRule.getProtocol(), action);
                        if (servicePorts.containsKey(destinationIP)) {
                            for (Integer svcPort : servicePorts.get(destinationIP)) {
                                updateEBPFMap(sourceIP, destinationIP, svcPort, egressRule.getProtocol(), action);
                            }
                        }
                    }
                }
            }

            // Process ingress rules
            System.out.println("Ingress rules:");
            for (IngressRule ingressRule : request.getIngressList()) {
                List<String> sourceIPs = new ArrayList<>();
                if (ingressRule.getRemoteType().equals("deployment")) {
                    sourceIPs.addAll(getPodIPsByDeployment(client, ingressRule.getRemoteNamespace(), ingressRule.getRemoteName()));
                } else if (ingressRule.getRemoteType().equals("namespace")) {
                    sourceIPs.addAll(getPodIPsByNamespace(client, ingressRule.getRemoteNamespace()));
                } else if (ingressRule.getRemoteType().equals("ips")) {
                    sourceIPs.addAll(parseIpList(ingressRule.getRemoteName()));
                } else if (ingressRule.getRemoteType().equals("namespace/deployment/ips")) {
                    // 处理复合类型
                    sourceIPs.addAll(getPodIPsByDeployment(client, ingressRule.getRemoteNamespace(), ingressRule.getRemoteName()));
                }

                for (String sourceIP : sourceIPs) {
                    List<String> destinationIPs = new ArrayList<>(targetPodIPs);
                    destinationIPs.addAll(targetServiceIPs);
                    Map<String, java.util.Set<Integer>> targetServicePorts = new HashMap<>();
                    if (targetObject.getType().equals("namespace/deployment")) {
                        targetServicePorts = getServicePortsByDeployment(client, targetNamespace, targetObject.getName(), ingressRule.getPort());
                    } else if (targetObject.getType().equals("namespace")) {
                        targetServicePorts = getServicePortsByNamespace(client, targetNamespace, ingressRule.getPort());
                    }
                    for (String destinationIP : destinationIPs) {
                        String action = ingressWhitelist ? "allow" : "drop";
                        System.out.printf("Source IP: %s, Destination IP: %s, Port: %d, Protocol: %s, Policy: %s%n",
                            sourceIP, destinationIP, ingressRule.getPort(), ingressRule.getProtocol(), action);
                        updateEBPFMap(sourceIP, destinationIP, ingressRule.getPort(), ingressRule.getProtocol(), action);
                        if (targetServicePorts.containsKey(destinationIP)) {
                            for (Integer svcPort : targetServicePorts.get(destinationIP)) {
                                updateEBPFMap(sourceIP, destinationIP, svcPort, ingressRule.getProtocol(), action);
                            }
                        }
                    }
                }
            }

        } catch (IOException | ApiException e) {
            e.printStackTrace();
        }
    }

    /**
     * 将规则转换为命令行参数并调用 update_map 更新 eBPF map。
     *
     * @param srcIP 源IP
     * @param dstIP 目标IP
     * @param port 端口
     * @param protocol 协议名
     * @param action 动作（accept/drop）
     */
    /**
     * 将规则转换为命令行参数并调用 update_map 更新 eBPF map。
     *
     * @param srcIP 源IP
     * @param dstIP 目标IP
     * @param port 端口
     * @param protocol 协议名
     * @param action 动作（allow/drop）
     */
    private static void updateEBPFMap(String srcIP, String dstIP, int port, String protocol, String action) {
        // 转换协议名称为数字
        int protoNum = 6; // 默认 TCP
        if (protocol.equalsIgnoreCase("UDP")) {
            protoNum = 17;
        } else if (protocol.equalsIgnoreCase("ICMP")) {
            protoNum = 1;
        }

        // 执行update_map命令
        String cmd = sudoPrefix + "./update_map add " + srcIP + " " + dstIP + " " + port + " " + protoNum + " " + action;
        executeCommand(cmd);
    }

    /**
     * 设置白名单管控方向掩码（1=ingress,2=egress）。
     *
     * @param ip 目标 Pod IP
     * @param mask 方向掩码
     */
    private static void setPolicyMode(String ip, int mask) {
        String cmd = sudoPrefix + "./update_map mode set " + ip + " " + mask;
        executeCommand(cmd);
    }

    /**
     * 判断是否为白名单模式。
     *
     * @param mode 模式
     * @return true=白名单
     */
    private static boolean isWhitelistMode(String mode) {
        return "whitelist".equalsIgnoreCase(mode);
    }

    /**
     * 解析方向级/全局模式，方向优先。
     *
     * @param specific 方向级模式
     * @param global 全局模式
     * @return 解析后的模式
     */
    private static String resolveMode(String specific, String global) {
        if (specific != null && !specific.isEmpty()) {
            return specific;
        }
        if (global != null && !global.isEmpty()) {
            return global;
        }
        return "blacklist";
    }

    /**
     * 执行外部命令并输出标准输出/错误。
     *
     * @param command 命令
     * @return 是否执行成功
     */
    private static boolean executeCommand(String command) {
        System.out.println("RUN: " + command);
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            // 读取输出和错误
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.err.println(line);
                }
            }
            return exitCode == 0;
        } catch (Exception e) {
            System.err.println("Error executing command: " + e.getMessage());
            return false;
        }
    }

    /**
     * 根据 Deployment 选择器获取 Pod IP 列表。
     *
     * @param client Kubernetes 客户端
     * @param namespace 命名空间
     * @param deploymentName Deployment 名称
     * @return Pod IP 列表
     * @throws ApiException Kubernetes API 异常
     */
    private static List<String> getPodIPsByDeployment(ApiClient client, String namespace, String deploymentName) throws ApiException {
        AppsV1Api appsApi = new AppsV1Api(client);
        V1Deployment deployment = appsApi.readNamespacedDeployment(deploymentName, namespace, null);
        V1DeploymentSpec spec = deployment.getSpec();
        if (spec == null || spec.getSelector() == null) {
            return new ArrayList<>();
        }
        V1LabelSelector selector = spec.getSelector();
        Map<String, String> matchLabels = selector.getMatchLabels();
        if (matchLabels == null || matchLabels.isEmpty()) {
            return new ArrayList<>();
        }
        StringBuilder labelSelector = new StringBuilder();
        for (Map.Entry<String, String> entry : matchLabels.entrySet()) {
            if (labelSelector.length() > 0) {
                labelSelector.append(",");
            }
            labelSelector.append(entry.getKey()).append("=").append(entry.getValue());
        }
        CoreV1Api coreApi = new CoreV1Api(client);
        V1PodList podList = coreApi.listNamespacedPod(namespace, null, null, null, null, labelSelector.toString(), null, null, null, null, null);
        List<String> podIPs = new ArrayList<>();
        for (V1Pod pod : podList.getItems()) {
            V1PodStatus status = pod.getStatus();
            if (status != null && status.getPodIP() != null) {
                podIPs.add(status.getPodIP());
            }
        }
        return podIPs;
    }

    /**
     * 获取命名空间下全部 Pod IP 列表。
     *
     * @param client Kubernetes 客户端
     * @param namespace 命名空间
     * @return Pod IP 列表
     * @throws ApiException Kubernetes API 异常
     */
    private static List<String> getPodIPsByNamespace(ApiClient client, String namespace) throws ApiException {
        CoreV1Api coreApi = new CoreV1Api(client);
        V1PodList podList = coreApi.listNamespacedPod(namespace, null, null, null, null, null, null, null, null, null, null);
        List<String> podIPs = new ArrayList<>();
        for (V1Pod pod : podList.getItems()) {
            V1PodStatus status = pod.getStatus();
            if (status != null && status.getPodIP() != null) {
                podIPs.add(status.getPodIP());
            }
        }
        return podIPs;
    }

    private static List<String> getServiceClusterIPsByDeployment(ApiClient client, String namespace, String deploymentName) throws ApiException {
        AppsV1Api appsApi = new AppsV1Api(client);
        V1Deployment deployment = appsApi.readNamespacedDeployment(deploymentName, namespace, null);
        V1DeploymentSpec spec = deployment.getSpec();
        if (spec == null || spec.getSelector() == null) {
            return new ArrayList<>();
        }
        V1LabelSelector selector = spec.getSelector();
        Map<String, String> matchLabels = selector.getMatchLabels();
        if (matchLabels == null || matchLabels.isEmpty()) {
            return new ArrayList<>();
        }
        CoreV1Api coreApi = new CoreV1Api(client);
        V1ServiceList serviceList = coreApi.listNamespacedService(namespace, null, null, null, null, null, null, null, null, null, null);
        List<String> ips = new ArrayList<>();
        for (V1Service service : serviceList.getItems()) {
            V1ServiceSpec svcSpec = service.getSpec();
            if (svcSpec == null) {
                continue;
            }
            Map<String, String> svcSelector = svcSpec.getSelector();
            if (svcSelector == null || svcSelector.isEmpty()) {
                continue;
            }
            boolean matches = true;
            for (Map.Entry<String, String> entry : svcSelector.entrySet()) {
                if (!entry.getValue().equals(matchLabels.get(entry.getKey()))) {
                    matches = false;
                    break;
                }
            }
            if (!matches) {
                continue;
            }
            addServiceClusterIPs(ips, svcSpec);
        }
        return ips;
    }

    private static List<String> getServiceClusterIPsByNamespace(ApiClient client, String namespace) throws ApiException {
        CoreV1Api coreApi = new CoreV1Api(client);
        V1ServiceList serviceList = coreApi.listNamespacedService(namespace, null, null, null, null, null, null, null, null, null, null);
        List<String> ips = new ArrayList<>();
        for (V1Service service : serviceList.getItems()) {
            V1ServiceSpec spec = service.getSpec();
            if (spec == null) {
                continue;
            }
            addServiceClusterIPs(ips, spec);
        }
        return ips;
    }

    private static void addServiceClusterIPs(List<String> ips, V1ServiceSpec spec) {
        if (spec == null) {
            return;
        }
        List<String> clusterIPs = spec.getClusterIPs();
        if (clusterIPs != null) {
            for (String ip : clusterIPs) {
                if (ip != null && !ip.isEmpty() && !"None".equalsIgnoreCase(ip)) {
                    ips.add(ip);
                }
            }
        }
        String clusterIP = spec.getClusterIP();
        if (clusterIP != null && !clusterIP.isEmpty() && !"None".equalsIgnoreCase(clusterIP)) {
            ips.add(clusterIP);
        }
    }

    private static Map<String, java.util.Set<Integer>> getServicePortsByDeployment(ApiClient client, String namespace, String deploymentName, int targetPort) throws ApiException {
        AppsV1Api appsApi = new AppsV1Api(client);
        V1Deployment deployment = appsApi.readNamespacedDeployment(deploymentName, namespace, null);
        V1DeploymentSpec spec = deployment.getSpec();
        Map<String, java.util.Set<Integer>> result = new HashMap<>();
        if (spec == null || spec.getSelector() == null) {
            return result;
        }
        V1LabelSelector selector = spec.getSelector();
        Map<String, String> matchLabels = selector.getMatchLabels();
        if (matchLabels == null || matchLabels.isEmpty()) {
            return result;
        }
        CoreV1Api coreApi = new CoreV1Api(client);
        V1ServiceList serviceList = coreApi.listNamespacedService(namespace, null, null, null, null, null, null, null, null, null, null);
        for (V1Service service : serviceList.getItems()) {
            V1ServiceSpec svcSpec = service.getSpec();
            if (svcSpec == null) {
                continue;
            }
            Map<String, String> svcSelector = svcSpec.getSelector();
            if (svcSelector == null || svcSelector.isEmpty()) {
                continue;
            }
            boolean matches = true;
            for (Map.Entry<String, String> entry : svcSelector.entrySet()) {
                if (!entry.getValue().equals(matchLabels.get(entry.getKey()))) {
                    matches = false;
                    break;
                }
            }
            if (!matches) {
                continue;
            }
            List<String> clusterIPs = new ArrayList<>();
            addServiceClusterIPs(clusterIPs, svcSpec);
            List<V1ServicePort> ports = svcSpec.getPorts();
            if (clusterIPs.isEmpty() || ports == null) {
                continue;
            }
            for (V1ServicePort port : ports) {
                if (port == null) {
                    continue;
                }
                if (!matchesTargetPort(port.getTargetPort(), targetPort, port.getPort())) {
                    continue;
                }
                for (String ip : clusterIPs) {
                    result.computeIfAbsent(ip, key -> new java.util.HashSet<>()).add(port.getPort());
                }
            }
        }
        return result;
    }

    private static Map<String, java.util.Set<Integer>> getServicePortsByNamespace(ApiClient client, String namespace, int targetPort) throws ApiException {
        CoreV1Api coreApi = new CoreV1Api(client);
        V1ServiceList serviceList = coreApi.listNamespacedService(namespace, null, null, null, null, null, null, null, null, null, null);
        Map<String, java.util.Set<Integer>> result = new HashMap<>();
        for (V1Service service : serviceList.getItems()) {
            V1ServiceSpec spec = service.getSpec();
            if (spec == null) {
                continue;
            }
            List<String> clusterIPs = new ArrayList<>();
            addServiceClusterIPs(clusterIPs, spec);
            List<V1ServicePort> ports = spec.getPorts();
            if (clusterIPs.isEmpty() || ports == null) {
                continue;
            }
            for (V1ServicePort port : ports) {
                if (port == null) {
                    continue;
                }
                if (!matchesTargetPort(port.getTargetPort(), targetPort, port.getPort())) {
                    continue;
                }
                for (String ip : clusterIPs) {
                    result.computeIfAbsent(ip, key -> new java.util.HashSet<>()).add(port.getPort());
                }
            }
        }
        return result;
    }

    private static boolean matchesTargetPort(IntOrString targetPort, int desiredPort, int servicePort) {
        if (targetPort == null) {
            return servicePort == desiredPort;
        }
        if (targetPort.isInteger()) {
            return targetPort.getIntValue() == desiredPort;
        }
        return false;
    }

    private static List<String> parseIpList(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        String[] parts = value.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}