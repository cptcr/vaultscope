module vaultscope {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.net.http;
    requires java.desktop;
    requires java.sql;
    requires java.prefs;

    opens dev.cptcr.vaultscope to javafx.fxml;
    opens dev.cptcr.vaultscope.controller to javafx.fxml;

    exports dev.cptcr.vaultscope;
    exports dev.cptcr.vaultscope.controller;
    exports dev.cptcr.vaultscope.model;
    exports dev.cptcr.vaultscope.service;
    exports dev.cptcr.vaultscope.util;
}