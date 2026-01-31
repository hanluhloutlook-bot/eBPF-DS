package com.example;

public class TargetObject {
    private String type;
    private String name;

    /**
     * 获取目标对象类型。
     *
     * @return 目标类型
     */
    public String getType() {
        return type;
    }

    /**
     * 设置目标对象类型。
     *
     * @param type 目标类型
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * 获取目标对象名称。
     *
     * @return 目标名称
     */
    public String getName() {
        return name;
    }

    /**
     * 设置目标对象名称。
     *
     * @param name 目标名称
     */
    public void setName(String name) {
        this.name = name;
    }
}