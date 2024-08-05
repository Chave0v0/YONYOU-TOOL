package com.chave.thread;

import javafx.scene.control.TextArea;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class MyThread extends Thread {
    private String vuln;
    private TextArea log;
    private TextArea execLog;
    private TextArea uploadLog;

    public MyThread(String vuln, TextArea log, TextArea execLog, TextArea uploadLog) {
        this.vuln = vuln;
        this.log = log;
        this.execLog = execLog;
        this.uploadLog = uploadLog;
    }

    @Override
    public void run() {
        try {

            Class<?> vulnClass = Class.forName("com.chave.vuln." + this.vuln);
            Method exploitMethod = vulnClass.getMethod("exploit");
            exploitMethod.invoke(vulnClass.getDeclaredConstructor(TextArea.class, TextArea.class, TextArea.class).newInstance(this.log, this.execLog, this.uploadLog));

        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }
}
