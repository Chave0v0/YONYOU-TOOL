package com.chave.proxy;

import java.net.MalformedURLException;
import java.net.URL;

public class HttpProxy {
    private boolean isProxy = false;
    private String httpProxy;
    private String httpProxyHost;
    private String httpProxyPort;

    public HttpProxy() {
        isProxy = false;
    }

    public HttpProxy(String httpProxy) throws MalformedURLException {
        isProxy = true;
        URL proxy_url = new URL(httpProxy);
        this.httpProxyHost = proxy_url.getHost();
        this.httpProxyPort = String.valueOf(proxy_url.getPort());
    }

    public String getHttpProxyHost() {
        return this.httpProxyHost;
    }

    public String getHttpProxyPort() {
        return this.httpProxyPort;
    }

    public boolean isProxy() {
        return isProxy;
    }
}
