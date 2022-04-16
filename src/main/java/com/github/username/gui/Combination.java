package com.github.username.gui;

public class Combination {
    private String key;
    private String value;

    public Combination(String key, String value) {
        this.key = key;
        this.value = value;
    }

    @Override 
    public String toString() { return key; }
    public String getKey()   { return key; }
    public String getValue() { return value; }
}
