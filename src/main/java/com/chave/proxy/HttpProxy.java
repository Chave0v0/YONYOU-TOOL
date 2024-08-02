package com.chave.proxy;

import java.net.MalformedURLException;
import java.net.URL;

public class HttpProxy {
    public static boolean IS_PROXY = false;
    public static String PROXY_HOST = "127.0.0.1";
    public static String PROXY_PORT = "8080";

    public static void setProxy() {
        if (HttpProxy.IS_PROXY == true) {
            System.setProperty("http.proxyHost", HttpProxy.PROXY_HOST);
            System.setProperty("http.proxyPort", HttpProxy.PROXY_PORT);
            System.setProperty("https.proxyHost", HttpProxy.PROXY_HOST);
            System.setProperty("https.proxyPort", HttpProxy.PROXY_PORT);
        }
    }
}
