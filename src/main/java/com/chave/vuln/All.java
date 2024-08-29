package com.chave.vuln;

import com.chave.config.Config;
import com.chave.thread.MyThread;
import javafx.scene.control.TextArea;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;

public class All extends VulnBase {
    public static boolean DNSLOG = true;
    public static boolean JNDI = false;
    public static boolean EXEC = false;
    public static boolean UPLOAD = false;
    public static boolean GETSHELL = false;

    public All() {
    }

    public All(TextArea log, TextArea execLog, TextArea uploadLog) {
        super(log, execLog, uploadLog);
    }

    @Override
    public void exploit() throws ClassNotFoundException, NoSuchFieldException, InstantiationException, IllegalAccessException {
        // 批量探测必须指定dnslog
        if (Config.DNSLOG == null || Config.DNSLOG.trim().isEmpty()) {
            logMessage("[-] 批量探测必须指定 DNSLOG.");
            return;
        }

        Class<?> mainControllerClass = Class.forName("com.chave.controller.MainController");
        Field mapField = mainControllerClass.getDeclaredField("map");
        mapField.setAccessible(true);
        HashMap map = (HashMap) mapField.get(mainControllerClass.newInstance());

        Collection<String> values = map.values();
        values.remove("All");

        MyThread[] threads = new MyThread[values.size()];
        int i = 0;
        for (String value : values) {
            MyThread myThread = new MyThread(value, this.log, this.execLog, this.uploadLog);
            threads[i++] = myThread;
        }

        for (MyThread thread : threads) {
            thread.start();
        }
    }
}
