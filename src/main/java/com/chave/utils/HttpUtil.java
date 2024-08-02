package com.chave.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

public class HttpUtil {
    public static String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";

    public static void get(HttpURLConnection conn) throws ProtocolException {
        // 设置请求方法为 GET
        conn.setRequestMethod("GET");
        conn.setRequestProperty("User-Agent", ua);

    }

    public static void post(HttpURLConnection conn, byte[] postData) throws IOException {
        // 仅设置 method、ua、host
        conn.setRequestMethod("POST");
        conn.setRequestProperty("User-Agent", ua);

        // 发送 POST 请求必须设置为 true
        conn.setDoOutput(true);

        // 发送请求体
        try (OutputStream os = conn.getOutputStream()) {
            os.write(postData, 0, postData.length);
        }
    }

    public static String getResponseText(HttpURLConnection conn) throws IOException {
        StringBuilder response = new StringBuilder();

        // 获取响应体内容
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim() + "\n");
            }
            return response.toString();
        }
    }

    public static int getResponseCode(HttpURLConnection conn) throws IOException {
        return conn.getResponseCode();
    }
}
