package com.chave.utils;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class Util {
    public static String DEFAULT_PATH = "./";

    public static void serialize(Object obj, String... serPath) throws IOException {
        String targetFilePath = DEFAULT_PATH + "ser.bin";
        if (serPath.length != 0) {
            targetFilePath = serPath[0];
        }
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(targetFilePath));
        oos.writeObject(obj);
    }

    public static byte[] getSerializedData(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        return bos.toByteArray();
    }

    public static Object unserialize(String... serFilePath) throws IOException, ClassNotFoundException {
        String targetFilePath = DEFAULT_PATH + "ser.bin";
        if (serFilePath.length != 0) {
            targetFilePath = serFilePath[0];
        }
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(targetFilePath));
        return ois.readObject();
    }

    public static String bcelEncode(String fileName, String... classFilePath) throws IOException {
        String filePath = DEFAULT_PATH + fileName;
        if (classFilePath.length != 0) {
            filePath = classFilePath[0] + fileName;
        }
        byte[] code = Files.readAllBytes(Paths.get(filePath));
        return  "$$BCEL$$" + com.sun.org.apache.bcel.internal.classfile.Utility.encode(code, true);
    }

    public static byte[] getFileByte(String fileName, String... filePath) throws IOException {
        String targetFilePath = DEFAULT_PATH + fileName;
        if (filePath.length != 0) {
            targetFilePath = filePath[0] + fileName;
        }
        byte[] code = Files.readAllBytes(Paths.get(targetFilePath));
        return code;
    }

    public static String byteCodeToBase64(byte[] code) {
        return DatatypeConverter.printBase64Binary(code);
    }

    public static byte[] base64ToByteCode(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    public static String fullyURLEncode(String input) throws UnsupportedEncodingException {
        StringBuilder encodedString = new StringBuilder();

        // Iterate over each character in the input string
        for (char ch : input.toCharArray()) {
            // Encode each character to its %XX format
            encodedString.append(String.format("%%%02X", (int) ch));
        }

        return encodedString.toString();
    }

    public static String unicodeEncode(String input) {
        StringBuilder unicodeBuilder = new StringBuilder();
        for (char c : input.toCharArray()) {
            unicodeBuilder.append("\\u");
            unicodeBuilder.append(String.format("%04x", (int) c));
        }
        return unicodeBuilder.toString();
    }
}