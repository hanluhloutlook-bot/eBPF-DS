package com.example;

import java.util.List;

public class NetworkPolicyRequest {
    private String clusterName;
    private String namespace;
    private String name;
    private TargetObject targetObject;
    private String createUser;
    private List<EgressRule> egressList;
    private List<IngressRule> ingressList;
    /**
     * 策略模式：whitelist/blacklist（全局）。
     */
    private String policyMode;
    /**
     * 入向策略模式：whitelist/blacklist（覆盖全局）。
     */
    private String ingressMode;
    /**
     * 出向策略模式：whitelist/blacklist（覆盖全局）。
     */
    private String egressMode;

    /**
     * 获取集群名称。
     *
     * @return 集群名称
     */
    public String getClusterName() {
        return clusterName;
    }

    /**
     * 设置集群名称。
     *
     * @param clusterName 集群名称
     */
    public void setClusterName(String clusterName) {
        this.clusterName = clusterName;
    }

    /**
     * 获取命名空间。
     *
     * @return 命名空间
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * 设置命名空间。
     *
     * @param namespace 命名空间
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * 获取策略名称。
     *
     * @return 策略名称
     */
    public String getName() {
        return name;
    }

    /**
     * 设置策略名称。
     *
     * @param name 策略名称
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * 获取目标对象。
     *
     * @return 目标对象
     */
    public TargetObject getTargetObject() {
        return targetObject;
    }

    /**
     * 设置目标对象。
     *
     * @param targetObject 目标对象
     */
    public void setTargetObject(TargetObject targetObject) {
        this.targetObject = targetObject;
    }

    /**
     * 获取创建人。
     *
     * @return 创建人
     */
    public String getCreateUser() {
        return createUser;
    }

    /**
     * 设置创建人。
     *
     * @param createUser 创建人
     */
    public void setCreateUser(String createUser) {
        this.createUser = createUser;
    }

    /**
     * 获取出站规则列表。
     *
     * @return 出站规则列表
     */
    public List<EgressRule> getEgressList() {
        return egressList;
    }

    /**
     * 设置出站规则列表。
     *
     * @param egressList 出站规则列表
     */
    public void setEgressList(List<EgressRule> egressList) {
        this.egressList = egressList;
    }

    /**
     * 获取入站规则列表。
     *
     * @return 入站规则列表
     */
    public List<IngressRule> getIngressList() {
        return ingressList;
    }

    /**
     * 设置入站规则列表。
     *
     * @param ingressList 入站规则列表
     */
    public void setIngressList(List<IngressRule> ingressList) {
        this.ingressList = ingressList;
    }

    /**
     * 获取整体策略模式（whitelist/blacklist）。
     *
     * @return 策略模式
     */
    public String getPolicyMode() {
        return policyMode;
    }

    /**
     * 设置整体策略模式（whitelist/blacklist）。
     *
     * @param policyMode 策略模式
     */
    public void setPolicyMode(String policyMode) {
        this.policyMode = policyMode;
    }

    /**
     * 获取入向策略模式（whitelist/blacklist）。
     *
     * @return 入向策略模式
     */
    public String getIngressMode() {
        return ingressMode;
    }

    /**
     * 设置入向策略模式（whitelist/blacklist）。
     *
     * @param ingressMode 入向策略模式
     */
    public void setIngressMode(String ingressMode) {
        this.ingressMode = ingressMode;
    }

    /**
     * 获取出向策略模式（whitelist/blacklist）。
     *
     * @return 出向策略模式
     */
    public String getEgressMode() {
        return egressMode;
    }

    /**
     * 设置出向策略模式（whitelist/blacklist）。
     *
     * @param egressMode 出向策略模式
     */
    public void setEgressMode(String egressMode) {
        this.egressMode = egressMode;
    }
}