module vaultscope {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.apache.httpcomponents.client5;
    requires org.apache.httpcomponents.core5;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.datatype.jsr310;
    requires org.slf4j;
    requires org.jsoup;

    opens dev.cptcr.vaultscope to javafx.fxml;
    opens dev.cptcr.vaultscope.controller to javafx.fxml;
    opens dev.cptcr.vaultscope.model to com.fasterxml.jackson.databind;

    exports dev.cptcr.vaultscope;
    exports dev.cptcr.vaultscope.controller;
    exports dev.cptcr.vaultscope.model;
    exports dev.cptcr.vaultscope.service;
}