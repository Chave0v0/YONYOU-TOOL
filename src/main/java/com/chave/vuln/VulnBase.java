package com.chave.vuln;

import javafx.application.Platform;
import javafx.scene.control.TextArea;

import java.io.IOException;

public abstract class VulnBase {
    public TextArea log;
    public TextArea uploadLog;
    public TextArea execLog;

    public VulnBase() {
    }

    public VulnBase(TextArea log, TextArea uploadLog, TextArea execLog) {
        this.log = log;
        this.uploadLog = uploadLog;
        this.execLog = execLog;
    }

    public void logMessage(String message) {
        if (log != null) {
            Platform.runLater(() -> log.appendText(message + "\n"));
        }
    }

    public void logUpload(String message) {
        if (uploadLog != null) {
            Platform.runLater(() -> uploadLog.appendText(message + "\n"));
        }
    }

    public void logExec(String message) {
        if (execLog != null) {
            Platform.runLater(() -> execLog.appendText(message + "\n"));
        }
    }

    public abstract void exploit() throws ClassNotFoundException, NoSuchFieldException, InstantiationException, IllegalAccessException, IOException;
}
