package com.example;

import java.io.*;
import java.net.*;

public class NetworkPolicyServer {

    private static final int PORT = 8090;
    private static volatile boolean running = true;
    private static String interfaceName = "ens33";
    private static String sudoPrefix = "";

    /**
     * 轻量级 HTTP 服务入口：加载 eBPF、挂载 tc 规则并等待请求。
     *
     * @param args 启动参数，可传接口名
     */
    public static void main(String[] args) {
        // 检查是否以root用户运行
        if (System.getProperty("user.name").equals("root")) {
            sudoPrefix = "";
        } else {
            sudoPrefix = "sudo ";
        }

        // 获取网络接口名称
        String envIf = System.getenv("IFACE");
        if (envIf != null && !envIf.isEmpty()) {
            interfaceName = envIf;
        }
        if (args.length >= 1 && args[0] != null && !args[0].isEmpty()) {
            interfaceName = args[0];
        }

        // 加载eBPF程序
        if (!loadEBPFPrograms()) {
            System.err.println("Failed to load eBPF programs");
            return;
        }

        // 挂载tc规则
        if (!attachTCRules()) {
            System.err.println("Failed to attach TC rules");
            cleanup();
            return;
        }

        // 启动HTTP服务器
        startHttpServer();

        // 注册关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                System.out.println("Shutting down...");
                running = false;
                cleanup();
            }
        }));

        // 等待中断
        while (running) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * 加载 eBPF 程序（当前由外部命令处理）。
     *
     * @return 是否成功
     */
    private static boolean loadEBPFPrograms() {
        System.out.println("Loading eBPF programs...");
        // eBPF程序加载由shell命令处理
        return true;
    }

    /**
     * 在指定网卡上挂载 ingress/egress tc 过滤器。
     *
     * @return 是否成功
     */
    private static boolean attachTCRules() {
        System.out.println("Attaching TC rules to interface: " + interfaceName);

        // 添加clsact qdisc
        String cmd1 = sudoPrefix + "tc qdisc add dev " + interfaceName + " clsact";
        if (!executeCommand(cmd1)) {
            return false;
        }

        // 添加ingress过滤器
        String cmd2 = sudoPrefix + "tc filter add dev " + interfaceName + " ingress bpf da obj tc_filter.bpf.o sec classifier";
        if (!executeCommand(cmd2)) {
            return false;
        }

        // 添加egress过滤器 - 注意：tc_filter.bpf.c 只包含ingress程序，所以这里也需要对应的egress程序
        // 由于只有一个tc_filter.bpf.o，我们需要创建一个对应的egress程序或复用现有程序
        String cmd3 = sudoPrefix + "tc filter add dev " + interfaceName + " egress bpf da obj tc_filter.bpf.o sec classifier";
        if (!executeCommand(cmd3)) {
            return false;
        }

        return true;
    }

    /**
     * 清理 tc 规则。
     */
    private static void cleanup() {
        System.out.println("Cleaning up TC rules...");
        String cmd = sudoPrefix + "tc qdisc del dev " + interfaceName + " clsact";
        executeCommand(cmd);
    }

    /**
     * 执行命令并输出日志。
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
            BufferedReader inputReader = null;
            BufferedReader errorReader = null;
            try {
                inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
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
                errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
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
     * 启动 HTTP 服务线程，监听规则更新请求。
     */
    private static void startHttpServer() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                ServerSocket serverSocket = null;
                try {
                    serverSocket = new ServerSocket(PORT);
                    System.out.println("HTTP server listening on port " + PORT);
                    while (running) {
                        try {
                            Socket clientSocket = serverSocket.accept();
                            handleClientRequest(clientSocket);
                        } catch (SocketTimeoutException e) {
                            // 超时异常，继续循环
                        } catch (IOException e) {
                            if (running) {
                                System.err.println("Error accepting client connection: " + e.getMessage());
                            }
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Error starting HTTP server: " + e.getMessage());
                } finally {
                    try {
                        if (serverSocket != null) {
                            serverSocket.close();
                        }
                    } catch (IOException e) {
                        System.err.println("Error closing server socket: " + e.getMessage());
                    }
                }
            }
        }).start();
    }

    /**
     * 处理单个客户端请求。
     *
     * @param clientSocket 客户端套接字
     */
    private static void handleClientRequest(Socket clientSocket) {
        BufferedReader in = null;
        PrintWriter out = null;
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            // 读取请求
            String requestLine = in.readLine();
            if (requestLine == null) {
                return;
            }

            System.out.println("Received request: " + requestLine);

            // 检查是否是GET /add请求
            if (requestLine.startsWith("GET /add?")) {
                // 解析查询参数
                int queryStart = requestLine.indexOf('?') + 1;
                int queryEnd = requestLine.indexOf(' ', queryStart);
                String queryString = requestLine.substring(queryStart, queryEnd);
                parseAndUpdateMap(queryString);

                // 发送响应
                out.println("HTTP/1.1 200 OK");
                out.println("Content-Type: text/plain");
                out.println();
                out.println("Rule Updated");
            } else {
                // 发送404响应
                out.println("HTTP/1.1 404 Not Found");
                out.println();
            }
        } catch (IOException e) {
            System.err.println("Error handling client request: " + e.getMessage());
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (out != null) {
                    out.close();
                }
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing resources: " + e.getMessage());
            }
        }
    }

    /**
     * 解析查询参数并调用 update_map 更新 eBPF map。
     *
     * @param queryString 查询字符串
     */
    private static void parseAndUpdateMap(String queryString) {
        String src = "";
        String dst = "";
        int port = 0;
        int proto = 6; // 默认 TCP
        String action = "";

        // 解析查询参数
        String[] params = queryString.split("&");
        for (String param : params) {
            String[] keyValue = param.split("=");
            if (keyValue.length != 2) {
                continue;
            }
            String key = keyValue[0];
            String value = keyValue[1];

            switch (key) {
                case "src":
                    src = value;
                    break;
                case "dst":
                    dst = value;
                    break;
                case "port":
                    try {
                        port = Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        System.err.println("Invalid port: " + value);
                    }
                    break;
                case "proto":
                    try {
                        proto = Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        System.err.println("Invalid proto: " + value);
                    }
                    break;
                case "action":
                    action = value;
                    break;
            }
        }

        if (src.isEmpty() || dst.isEmpty()) {
            System.err.println("Invalid params: missing src or dst");
            return;
        }

        // 执行更新eBPF map的命令
        // 注意：这里需要一个C程序来更新eBPF map，因为Java不能直接操作eBPF map
        // 我们可以创建一个简单的C程序，接受命令行参数，更新eBPF map
        String updateCmd = sudoPrefix + "./update_map add " + src + " " + dst + " " + port + " " + proto + " " + action;
        executeCommand(updateCmd);
    }
}
