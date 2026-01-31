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
import io.kubernetes.client.util.Config;
import org.springframework.web.bind.annotation.*;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/networkpolicy")
public class NetworkPolicyController {

    private String sudoPrefix = "";
    private boolean useSimplifiedMode = false;
    /**
     * 当前节点名称（由环境变量 NODE_NAME 注入），用于筛选本节点 Pod。
     */
    private final String nodeName = System.getenv("NODE_NAME");

    /**
     * 全量策略缓存（外部管理端下发的策略集合）。
     */
    private static final List<NetworkPolicyRequest> POLICY_CACHE = new CopyOnWriteArrayList<>();
    /**
     * 本节点已下发的规则集合，用于差异更新。
     */
    private final Set<RuleKey> lastAppliedRules = ConcurrentHashMap.newKeySet();
    /**
     * 本节点已设置的白名单管控模式集合，用于差异更新。
     */
    private final Set<PolicyModeKey> lastAppliedModes = ConcurrentHashMap.newKeySet();

    /**
     * 初始化控制器并根据当前用户设置 sudo 前缀。
     */
    public NetworkPolicyController() {
        // 检查是否以root用户运行
        if (System.getProperty("user.name").equals("root")) {
            sudoPrefix = "";
        } else {
            sudoPrefix = "sudo ";
        }
    }

    private static class RuleKey {
        /** 源IP */
        private final String src;
        /** 目标IP */
        private final String dst;
        /** 端口 */
        private final int port;
        /** 协议号 */
        private final int proto;
        /** 动作（allow/drop） */
        private final String action;

        private RuleKey(String src, String dst, int port, int proto, String action) {
            this.src = src;
            this.dst = dst;
            this.port = port;
            this.proto = proto;
            this.action = action;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof RuleKey)) {
                return false;
            }
            RuleKey ruleKey = (RuleKey) o;
            return port == ruleKey.port
                    && proto == ruleKey.proto
                    && Objects.equals(src, ruleKey.src)
                    && Objects.equals(dst, ruleKey.dst)
                    && Objects.equals(action, ruleKey.action);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst, port, proto, action);
        }
    }

    private static class PolicyModeKey {
        /** Pod IP */
        private final String ip;
        /** 方向掩码（1=ingress,2=egress） */
        private final int mask;

        private PolicyModeKey(String ip, int mask) {
            this.ip = ip;
            this.mask = mask;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof PolicyModeKey)) {
                return false;
            }
            PolicyModeKey that = (PolicyModeKey) o;
            return mask == that.mask && Objects.equals(ip, that.ip);
        }

        @Override
        public int hashCode() {
            return Objects.hash(ip, mask);
        }
    }

    @PostMapping("/create")
    /**
     * 创建网络策略：解析请求并写入 eBPF 规则。
     *
     * @param request 网络策略请求
     * @return 处理结果
     */
    public String createNetworkPolicy(@RequestBody NetworkPolicyRequest request) {
        try {
            cachePolicy(request);
            reconcileLocalRules();
            return "Network policy created successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error creating network policy: " + e.getMessage();
        }
    }

    @PostMapping("/delete")
    /**
     * 删除网络策略：根据请求删除 eBPF 规则。
     *
     * @param request 网络策略请求
     * @return 处理结果
     */
    public String deleteNetworkPolicy(@RequestBody NetworkPolicyRequest request) {
        try {
            removePolicy(request);
            reconcileLocalRules();
            return "Network policy deleted successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error deleting network policy: " + e.getMessage();
        }
    }

    /**
     * 周期性重新计算本节点需要的规则并同步到 eBPF map。
     */
    @Scheduled(fixedDelayString = "${policy.reconcile.interval.ms:30000}")
    public void reconcileLocalRules() {
        // 定时对齐本节点规则：只下发与本节点 Pod 相关的规则
        if (POLICY_CACHE.isEmpty()) {
            return;
        }

        boolean simplifiedAllowed = isSimplifiedModeEnabled();
        useSimplifiedMode = simplifiedAllowed;

        ApiClient client = null;
        try {
            client = Config.defaultClient();
            Configuration.setDefaultApiClient(client);
        } catch (Exception e) {
            if (!simplifiedAllowed) {
                System.err.println("Failed to connect to Kubernetes API server. Set SIMPLIFIED_MODE=1 to allow fallback.");
                return;
            }
        }

        // 获取本节点 Pod IP 列表
        Set<String> localPodIPs = new HashSet<>();
        if (client != null && nodeName != null && !nodeName.isEmpty()) {
            try {
                localPodIPs.addAll(getPodIPsByNode(client, nodeName));
            } catch (Exception e) {
                System.err.println("Failed to get local pods by node, skipping reconcile: " + e.getMessage());
                return;
            }
        }

        // 期望下发的规则集合、白名单管控集合
        Set<RuleKey> desiredRules = new HashSet<>();
        Map<String, Integer> desiredModeMap = new java.util.HashMap<>();

        for (NetworkPolicyRequest request : POLICY_CACHE) {
            // 白名单/黑名单模式解析（支持全局+按方向覆盖）
            String ingressMode = resolveMode(request.getIngressMode(), request.getPolicyMode());
            String egressMode = resolveMode(request.getEgressMode(), request.getPolicyMode());
            boolean ingressWhitelist = isWhitelistMode(ingressMode);
            boolean egressWhitelist = isWhitelistMode(egressMode);

            List<String> targetPodIPs = new ArrayList<>();
            TargetObject targetObject = request.getTargetObject();

            if (useSimplifiedMode || client == null || targetObject == null) {
                targetPodIPs.add("10.0.0.1");
            } else if ("namespace/deployment".equals(targetObject.getType())) {
                try {
                    targetPodIPs.addAll(getPodIPsByDeployment(client, request.getNamespace(), targetObject.getName()));
                } catch (Exception e) {
                    System.err.println("Failed to get target pods: " + e.getMessage());
                    continue;
                }
            }

            // 只保留本节点 Pod IP
            if (!localPodIPs.isEmpty()) {
                targetPodIPs.removeIf(ip -> !localPodIPs.contains(ip));
            }

            if (targetPodIPs.isEmpty()) {
                continue;
            }

            // 白名单模式：记录被管控 Pod 的方向掩码
            if (egressWhitelist || ingressWhitelist) {
                for (String ip : targetPodIPs) {
                    int mask = desiredModeMap.getOrDefault(ip, 0);
                    if (egressWhitelist) {
                        mask |= 2;
                    }
                    if (ingressWhitelist) {
                        mask |= 1;
                    }
                    desiredModeMap.put(ip, mask);
                }
            }

            if (request.getEgressList() != null) {
                for (EgressRule egressRule : request.getEgressList()) {
                    List<String> destinationIPs = resolveRemoteIPs(client, egressRule.getRemoteType(), egressRule.getRemoteNamespace(), egressRule.getRemoteName());
                    for (String sourceIP : targetPodIPs) {
                        for (String destinationIP : destinationIPs) {
                            String action = egressWhitelist ? "allow" : "drop";
                            int protoNum = protocolToNumber(egressRule.getProtocol());
                            desiredRules.add(new RuleKey(sourceIP, destinationIP, egressRule.getPort(), protoNum, action));
                        }
                    }
                }
            }

            if (request.getIngressList() != null) {
                for (IngressRule ingressRule : request.getIngressList()) {
                    List<String> sourceIPs = resolveRemoteIPs(client, ingressRule.getRemoteType(), ingressRule.getRemoteNamespace(), ingressRule.getRemoteName());
                    for (String sourceIP : sourceIPs) {
                        for (String destinationIP : targetPodIPs) {
                            String action = ingressWhitelist ? "allow" : "drop";
                            int protoNum = protocolToNumber(ingressRule.getProtocol());
                            desiredRules.add(new RuleKey(sourceIP, destinationIP, ingressRule.getPort(), protoNum, action));
                        }
                    }
                }
            }
        }

        // 计算差异并更新 eBPF map
        Set<RuleKey> toAdd = new HashSet<>(desiredRules);
        toAdd.removeAll(lastAppliedRules);

        Set<RuleKey> toRemove = new HashSet<>(lastAppliedRules);
        toRemove.removeAll(desiredRules);

        for (RuleKey rule : toRemove) {
            deleteEBPFMap(rule.src, rule.dst, rule.port, rule.proto);
        }

        for (RuleKey rule : toAdd) {
            updateEBPFMap(rule.src, rule.dst, rule.port, String.valueOf(rule.proto), rule.action);
        }

        // 计算白名单管控差异并更新 policy_mode map
        Set<PolicyModeKey> desiredModes = new HashSet<>();
        for (Map.Entry<String, Integer> entry : desiredModeMap.entrySet()) {
            desiredModes.add(new PolicyModeKey(entry.getKey(), entry.getValue()));
        }

        Set<PolicyModeKey> toAddModes = new HashSet<>(desiredModes);
        toAddModes.removeAll(lastAppliedModes);

        Set<PolicyModeKey> toRemoveModes = new HashSet<>(lastAppliedModes);
        toRemoveModes.removeAll(desiredModes);

        for (PolicyModeKey mode : toRemoveModes) {
            clearPolicyMode(mode.ip);
        }

        for (PolicyModeKey mode : toAddModes) {
            setPolicyMode(mode.ip, mode.mask);
        }

        lastAppliedRules.clear();
        lastAppliedRules.addAll(desiredRules);
        lastAppliedModes.clear();
        lastAppliedModes.addAll(desiredModes);
    }

    @PostMapping("/add-rule")
    /**
     * 通过参数直接新增一条 eBPF 规则。
     *
     * @param src 源IP
     * @param dst 目标IP
     * @param port 端口
     * @param proto 协议号
     * @param action 动作（accept/drop）
     * @return 处理结果
     */
    public String addRule(@RequestParam String src, @RequestParam String dst, @RequestParam int port, 
                         @RequestParam int proto, @RequestParam String action) {
        try {
            String cmd = sudoPrefix + "./update_map add " + src + " " + dst + " " + port + " " + proto + " " + action;
            executeCommand(cmd);
            return "Rule added successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error adding rule: " + e.getMessage();
        }
    }

    @PostMapping("/delete-rule")
    /**
     * 通过参数删除一条 eBPF 规则。
     *
     * @param src 源IP
     * @param dst 目标IP
     * @param port 端口
     * @param proto 协议号
     * @return 处理结果
     */
    public String deleteRule(@RequestParam String src, @RequestParam String dst, @RequestParam int port,
                             @RequestParam int proto) {
        try {
            String cmd = sudoPrefix + "./update_map delete " + src + " " + dst + " " + port + " " + proto;
            executeCommand(cmd);
            return "Rule deleted successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error deleting rule: " + e.getMessage();
        }
    }

    @PostMapping("/start-ebpf")
    /**
     * 启动 eBPF 并在指定网卡挂载 tc 规则。
     *
     * @param interfaceName 网卡名
     * @return 处理结果
     */
    public String startEBPF(@RequestParam String interfaceName) {
        try {
            // 执行update_map start命令
            String cmd = sudoPrefix + "./update_map start " + interfaceName;
            executeCommand(cmd);
            return "successfully start EBPF service";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error starting EBPF program: " + e.getMessage();
        }
    }

    @PostMapping("/stop-ebpf")
    /**
     * 停止 eBPF：清理网卡上的 tc 规则。
     *
     * @param interfaceName 网卡名
     * @return 处理结果
     */
    public String stopEBPF(@RequestParam String interfaceName) {
        try {
            // 清理tc规则
            String cmd = sudoPrefix + "tc qdisc del dev " + interfaceName + " clsact";
            executeCommand(cmd);
            return "EBPF program stopped successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error stopping EBPF program: " + e.getMessage();
        }
    }

    @GetMapping("/query")
    /**
     * 查询 eBPF map 中的规则列表。
     *
     * @return 规则列表或错误信息
     */
    public String queryEBPFMap() {
        try {
            String cmd = sudoPrefix + "./update_map query";
            return executeCommandWithOutput(cmd);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error querying eBPF map: " + e.getMessage();
        }
    }

    private void cachePolicy(NetworkPolicyRequest request) {
        // 以 namespace/name 作为主键更新缓存
        String key = policyKey(request);
        POLICY_CACHE.removeIf(item -> policyKey(item).equals(key));
        POLICY_CACHE.add(request);
    }

    private void removePolicy(NetworkPolicyRequest request) {
        // 删除指定策略
        String key = policyKey(request);
        POLICY_CACHE.removeIf(item -> policyKey(item).equals(key));
    }

    private String policyKey(NetworkPolicyRequest request) {
        // 生成策略缓存主键
        if (request == null) {
            return "null";
        }
        if (request.getNamespace() != null && request.getName() != null) {
            return request.getNamespace() + "/" + request.getName();
        }
        return JSON.toJSONString(request);
    }

    private boolean isSimplifiedModeEnabled() {
        // 仅在允许简化模式时使用占位 IP
        return "1".equals(System.getenv("SIMPLIFIED_MODE"));
    }

    private String resolveMode(String specific, String global) {
        // 方向级模式优先，其次全局模式
        if (specific != null && !specific.isEmpty()) {
            return specific;
        }
        if (global != null && !global.isEmpty()) {
            return global;
        }
        return "blacklist";
    }

    private boolean isWhitelistMode(String mode) {
        // whitelist 表示未命中即拒绝
        return "whitelist".equalsIgnoreCase(mode);
    }

    private int protocolToNumber(String protocol) {
        // 协议名/数字统一转换为协议号
        if (protocol == null) {
            return 6;
        }
        if (protocol.matches("\\d+")) {
            return Integer.parseInt(protocol);
        }
        if (protocol.equalsIgnoreCase("UDP")) {
            return 17;
        } else if (protocol.equalsIgnoreCase("ICMP")) {
            return 1;
        }
        return 6;
    }

    private List<String> resolveRemoteIPs(ApiClient client, String remoteType, String remoteNamespace, String remoteName) {
        // 解析远端对象为 IP 列表（deployment/namespace/ips）
        List<String> result = new ArrayList<>();
        if (useSimplifiedMode || client == null) {
            if ("deployment".equals(remoteType)) {
                result.add("10.0.0.2");
            } else if ("namespace".equals(remoteType)) {
                result.add("10.0.0.3");
            } else if ("ips".equals(remoteType)) {
                result.add(remoteName);
            } else if ("namespace/deployment/ips".equals(remoteType)) {
                result.add("10.0.0.6");
            }
            return result;
        }

        try {
            if ("deployment".equals(remoteType)) {
                result.addAll(getPodIPsByDeployment(client, remoteNamespace, remoteName));
            } else if ("namespace".equals(remoteType)) {
                result.addAll(getPodIPsByNamespace(client, remoteNamespace));
            } else if ("ips".equals(remoteType)) {
                result.add(remoteName);
            } else if ("namespace/deployment/ips".equals(remoteType)) {
                result.addAll(getPodIPsByDeployment(client, remoteNamespace, remoteName));
            }
        } catch (Exception e) {
            System.err.println("Failed to resolve remote IPs: " + e.getMessage());
        }

        return result;
    }

    /**
     * 执行命令并返回标准输出内容。
     *
     * @param command 命令
     * @return 输出内容或错误信息
     */
    private String executeCommandWithOutput(String command) {
        System.out.println("RUN: " + command);
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();

            java.io.BufferedReader inputReader = null;
            java.io.BufferedReader errorReader = null;
            try {
                inputReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
                String line;
                boolean firstLine = true;
                while ((line = inputReader.readLine()) != null) {
                    if (!firstLine) {
                        output.append("\n");
                    }
                    output.append(line);
                    firstLine = false;
                }
            } finally {
                if (inputReader != null) {
                    try {
                        inputReader.close();
                    } catch (IOException e) {
                    }
                }
            }
            try {
                errorReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getErrorStream()));
                String line;
                while ((line = errorReader.readLine()) != null) {
                    System.err.println(line);
                }
            } finally {
                if (errorReader != null) {
                    try {
                        errorReader.close();
                    } catch (IOException e) {
                    }
                }
            }

            if (exitCode != 0) {
                return "Error: Command failed with exit code " + exitCode;
            }

            String result = output.toString();
            if (result.isEmpty()) {
                return "Map is empty or query failed.";
            }
            return result;
        } catch (Exception e) {
            System.err.println("Error executing command: " + e.getMessage());
            return "Error executing command: " + e.getMessage();
        }
    }

    /**
     * 更新 eBPF map：将规则写入内核。
     *
     * @param srcIP 源IP
     * @param dstIP 目标IP
     * @param port 端口
     * @param protocol 协议名
     * @param action 动作（accept/drop）
     */
    private void updateEBPFMap(String srcIP, String dstIP, int port, String protocol, String action) {
        // 通过 update_map add 写入规则
        int protoNum = protocolToNumber(protocol);

        String cmd = sudoPrefix + "./update_map add " + srcIP + " " + dstIP + " " + port + " " + protoNum + " " + action;
        executeCommand(cmd);
    }

    /**
     * 删除 eBPF map 中的规则。
     *
     * @param srcIP 源IP
     * @param dstIP 目标IP
     * @param port 端口
     * @param proto 协议号
     */
    private void deleteEBPFMap(String srcIP, String dstIP, int port, int proto) {
        // 通过 update_map delete 删除规则
        String cmd = sudoPrefix + "./update_map delete " + srcIP + " " + dstIP + " " + port + " " + proto;
        executeCommand(cmd);
    }

    private void setPolicyMode(String ip, int mask) {
        // 设置白名单管控方向掩码
        String cmd = sudoPrefix + "./update_map mode set " + ip + " " + mask;
        executeCommand(cmd);
    }

    private void clearPolicyMode(String ip) {
        // 清理白名单管控方向
        String cmd = sudoPrefix + "./update_map mode del " + ip;
        executeCommand(cmd);
    }

    /**
     * 执行命令并输出日志。
     *
     * @param command 命令
     * @return 是否执行成功
     */
    private boolean executeCommand(String command) {
        System.out.println("RUN: " + command);
        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            // 读取输出和错误
            java.io.BufferedReader inputReader = null;
            java.io.BufferedReader errorReader = null;
            try {
                inputReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
                String line;
                while ((line = inputReader.readLine()) != null) {
                    System.out.println(line);
                }
            } finally {
                if (inputReader != null) {
                    try {
                        inputReader.close();
                    } catch (IOException e) {
                        // 忽略关闭异常
                    }
                }
            }
            try {
                errorReader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getErrorStream()));
                String line;
                while ((line = errorReader.readLine()) != null) {
                    System.err.println(line);
                }
            } finally {
                if (errorReader != null) {
                    try {
                        errorReader.close();
                    } catch (IOException e) {
                        // 忽略关闭异常
                    }
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
    private List<String> getPodIPsByDeployment(ApiClient client, String namespace, String deploymentName) throws ApiException {
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
    private List<String> getPodIPsByNamespace(ApiClient client, String namespace) throws ApiException {
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

    private List<String> getPodIPsByNode(ApiClient client, String node) throws ApiException {
        // 查询本节点所有 Pod IP，用于本节点规则对齐
        CoreV1Api coreApi = new CoreV1Api(client);
        String fieldSelector = "spec.nodeName=" + node;
        V1PodList podList = coreApi.listPodForAllNamespaces(null, null, null, fieldSelector, null, null, null, null, null, null);
        List<String> podIPs = new ArrayList<>();
        for (V1Pod pod : podList.getItems()) {
            V1PodStatus status = pod.getStatus();
            if (status != null && status.getPodIP() != null) {
                podIPs.add(status.getPodIP());
            }
        }
        return podIPs;
    }
}
