package com.chave.main;

import com.chave.bean.Information;
import com.chave.proxy.HttpProxy;
import java.lang.reflect.Method;

public class Main {
    public static void main(String[] args) {
        //  创建information对象用于存储信息
        Information information = new Information();

        //  参数-h、-mod、-target、-proxy、-dnslog、-vuln
        try {
            //  输出帮助
            for (String arg : args) {
                if (arg.equals("-h") || arg.equals("--help")) {
                    System.out.println(Information.HELP);
                    return;
                }
            }

            //  处理参数
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("-m") || args[i].equals("--mod")) {
                    Information.MOD = args[i + 1];
                } else if (args[i].equals("-t") || args[i].equals("--target")) {
                    if (args[i + 1].endsWith("/")) {
                        args[i + 1] = args[i + 1].substring(0, args[i + 1].length() - 1);
                    }
                    Information.TARGET = args[i + 1];
                } else if (args[i].equals("-p") || args[i].equals("--proxy")) {
                    Information.PROXY = args[i + 1];
                } else if (args[i].equals("-d") || args[i].equals("--dnslog")) {
                    Information.DNSLOG = args[i + 1];
                } else if (args[i].equals("-v") || args[i].equals("--vuln")) {
                    Information.VULN = args[i + 1];
                }
            }

            //  创建HttpProxy对象用于http代理
            HttpProxy proxy = null;
            if (Information.PROXY != null) {
                proxy = new HttpProxy(Information.PROXY);
            } else {
                proxy = new HttpProxy();
            }

            //  漏洞检测、利用
            Class<?> vulnClass = Class.forName("com.chave.vuln." + Information.VULN);
            Method exploitMethod = vulnClass.getDeclaredMethod("exploit", HttpProxy.class);
            exploitMethod.invoke(vulnClass.newInstance(), proxy);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(Information.HELP);
        }

    }
}
