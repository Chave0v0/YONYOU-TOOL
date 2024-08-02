package com.chave.controller;

import com.chave.proxy.HttpProxy;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

public class ProxyController {
    @FXML
    private CheckBox proxyOn;

    @FXML
    private CheckBox proxyOff;

    @FXML
    private TextField hostField;

    @FXML
    private TextField portField;

    @FXML
    private Button submitButton;

    @FXML
    private Button cancelButton;

    @FXML
    public void initialize() {
        // 根据 HttpProxy.IS_PROXY 设置 CheckBox 的选中状态
        if (HttpProxy.IS_PROXY) {
            proxyOn.setSelected(true);
            proxyOff.setSelected(false);
        } else {
            proxyOn.setSelected(false);
            proxyOff.setSelected(true);
        }

        // 设置 hosts、port 默认值
        hostField.setText(HttpProxy.PROXY_HOST);
        portField.setText(HttpProxy.PROXY_PORT);

        proxyOn.setOnAction(event -> {
            if (proxyOn.isSelected()) {
                proxyOff.setSelected(false);
                HttpProxy.IS_PROXY = true;
            }
        });

        proxyOff.setOnAction(event -> {
            if (proxyOff.isSelected()) {
                proxyOn.setSelected(false);
                HttpProxy.IS_PROXY = false;
            }
        });

        submitButton.setOnAction(event -> {
            if (proxyOn.isSelected()) {
                String host = hostField.getText();
                String port = portField.getText();

                if (host.isEmpty() || port.isEmpty()) {
                    Stage stage = new Stage();
                    Label label = new Label("host与port不能为空!");
                    Scene scene = new Scene(label, 300, 200);
                    stage.setScene(scene);
                    stage.setWidth(300);
                    stage.setHeight(200);
                    stage.show();
                    return;
                }

                HttpProxy.PROXY_HOST = host;
                HttpProxy.PROXY_PORT = port;
            }

            closeStage();
        });

        cancelButton.setOnAction(event -> closeStage());

    }

    private void closeStage() {
        Stage stage = (Stage) submitButton.getScene().getWindow();
        stage.close();
    }
}
