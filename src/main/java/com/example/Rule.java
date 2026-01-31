package com.example;

public class Rule {
    private String protocol;
    private int port;
    private String remoteType;
    private String remoteNamespace;
    private String remoteName;

    /**
     * 获取协议类型（TCP/UDP/ICMP）。
     *
     * @return 协议字符串
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * 设置协议类型（TCP/UDP/ICMP）。
     *
     * @param protocol 协议字符串
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * 获取端口号。
     *
     * @return 端口号
     */
    public int getPort() {
        return port;
    }

    /**
     * 设置端口号。
     *
     * @param port 端口号
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * 获取远端对象类型。
     *
     * @return 远端对象类型
     */
    public String getRemoteType() {
        return remoteType;
    }

    /**
     * 设置远端对象类型。
     *
     * @param remoteType 远端对象类型
     */
    public void setRemoteType(String remoteType) {
        this.remoteType = remoteType;
    }

    /**
     * 获取远端命名空间。
     *
     * @return 远端命名空间
     */
    public String getRemoteNamespace() {
        return remoteNamespace;
    }

    /**
     * 设置远端命名空间。
     *
     * @param remoteNamespace 远端命名空间
     */
    public void setRemoteNamespace(String remoteNamespace) {
        this.remoteNamespace = remoteNamespace;
    }

    /**
     * 获取远端对象名称或IP。
     *
     * @return 远端名称或IP
     */
    public String getRemoteName() {
        return remoteName;
    }

    /**
     * 设置远端对象名称或IP。
     *
     * @param remoteName 远端名称或IP
     */
    public void setRemoteName(String remoteName) {
        this.remoteName = remoteName;
    }
}