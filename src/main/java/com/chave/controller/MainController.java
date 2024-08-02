package com.chave.controller;

import com.chave.bean.Config;
import com.chave.vuln.VulnBase;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.Pane;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class MainController {
    @FXML
    MenuItem proxy;

    @FXML
    ChoiceBox vulnChoiceBox;

    @FXML
    TextField dnslogField;

    @FXML
    TextField jndiField;

    @FXML
    TextField targetField;

    @FXML
    Button poc;

    @FXML
    TextArea log;

    @FXML
    Tab uploadTab;

    @FXML
    TextArea fileTextArea;

    @FXML
    TextArea execLog;

    @FXML
    TextArea uploadLog;

    @FXML
    Tab execTab;

    @FXML
    TextField cmdField;

    @FXML
    TextField fileNameField;

    @FXML
    Button uploadButton;


    @FXML
    public void initialize() {
        // 初始化 ChoiceBox 的选项
        vulnChoiceBox.setItems(FXCollections.observableArrayList(
                "ActionHandlerServlet",
                "Lfw_Core_Rpc_Upload"
        ));

        // 初始化提示内容
        dnslogField.setPromptText("xxxxx.dnslog.cn 等");
        jndiField.setPromptText("ldap://1.1.1.1:1389/abc");
        targetField.setPromptText("http://1.1.1.1:8080/");


        // ChoiceBox 添加选择项改变监听器
        vulnChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            Config.VULN = (String) newValue;

            // 判断是否支持dnslog探测 jndi利用
            try {
                Class<?> vulnClass = Class.forName("com.chave.vuln." + Config.VULN);
                Field dnslog_support_Field = vulnClass.getDeclaredField("DNSLOG");
                Field jndi_support_Field = vulnClass.getDeclaredField("JNDI");
                Field upload_support_Field = vulnClass.getDeclaredField("UPLOAD");
                Field exec_support_Field = vulnClass.getDeclaredField("EXEC");
                // 是否支持dnslog
                if (dnslog_support_Field.get(null).equals(false)) {
                    dnslogField.setEditable(false);
                    dnslogField.setStyle("-fx-background-color: lightgrey");
                    // 设置提示文本
                    dnslogField.setPromptText("");
                    dnslogField.setText("");
                } else {
                    dnslogField.setEditable(true);
                    dnslogField.setStyle("-fx-background-color: white");
                    // 设置提示文本
                    dnslogField.setPromptText("xxxxx.dnslog.cn 等");
                }
                // 是否支持jndi
                if (jndi_support_Field.get(null).equals(false)) {
                    jndiField.setEditable(false);
                    jndiField.setStyle("-fx-background-color: lightgrey");
                    // 设置提示文本
                    jndiField.setPromptText("");
                    dnslogField.setText("");
                } else {
                    jndiField.setEditable(true);
                    jndiField.setStyle("-fx-background-color: white");
                    // 设置提示文本
                    jndiField.setPromptText("ldap://1.1.1.1:1389/abc");
                }
                // 是否支持文件上传
                if (upload_support_Field.get(null).equals(false)) {
                    uploadTab.setDisable(true);

                } else {
                    uploadTab.setDisable(false);
                }
                // 是否支持命令执行
                if (exec_support_Field.get(null).equals(false)) {
                    execTab.setDisable(true);
                } else {
                    execTab.setDisable(false);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        // 修改target配置
        targetField.textProperty().addListener((observable, oldValue, newValue) -> {
            Config.TARGET = newValue;
        });

        // 修改dnslog配置
        dnslogField.textProperty().addListener((observable, oldValue, newValue) -> {
            Config.DNSLOG = newValue;
        });

        // 修改cmd配置
        cmdField.textProperty().addListener((observable, oldValue, newValue) -> {
            Config.CMD = newValue;
        });

        // 修改上传文件名配置
        fileNameField.textProperty().addListener((observable, oldValue, newValue) -> {
            Config.FILENAME = newValue;
        });

        // 获取上传文件内容
        fileTextArea.textProperty().addListener((observable, oldValue, newValue) -> {
            Config.FILETEXT = newValue;
        });


    }

    @FXML
    private void poc() {
        Config.MOD = "poc";
        checkTargetURL();
        exploit();
    }

    @FXML
    private void exp() {
        Config.MOD = "exp";
        checkTargetURL();
        exploit();
    }

    @FXML
    private void exec() {
        Config.MOD = "exec";
        checkTargetURL();
        exploit();
    }

    @FXML
    private void fileUpload() {
        Config.MOD = "upload";
        checkTargetURL();
        exploit();
    }

    private void checkTargetURL() {
        if (Config.TARGET.trim().endsWith("/")) {
            Config.TARGET = Config.TARGET.substring(0, Config.TARGET.length() - 1);
        }
    }

    private void exploit() {
        try {
            Class<?> vulnClass = Class.forName("com.chave.vuln." + Config.VULN);
            Method exploitMethod = VulnBase.class.getMethod("exploit");
            exploitMethod.invoke(vulnClass.getDeclaredConstructor(TextArea.class, TextArea.class, TextArea.class).newInstance(log, execLog, uploadLog));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void setProxy() throws IOException {
        Pane root = FXMLLoader.load(getClass().getClassLoader().getResource("Proxy.fxml"));

        Scene scene = new Scene(root, 230, 250);

        Stage stage = new Stage();
        stage.setScene(scene);
        stage.setTitle("设置http代理");
        stage.initModality(Modality.APPLICATION_MODAL);
        stage.setWidth(230);
        stage.setWidth(250);
        stage.setResizable(false);
        stage.show();
    }
}