package burp.Ui;

import java.awt.*;
import java.util.List;
import java.util.ArrayList;
import javax.swing.*;

import burp.IBurpExtenderCallbacks;
import burp.Bootstrap.YamlReader;

public class BaseSettingTag {
    private YamlReader yamlReader;

    private JCheckBox isStartBox;

    private JCheckBox isScanGetBox;
    private JCheckBox isScanPostBox;
    private JCheckBox isScanCookieBox;
    private JCheckBox isScanJsonBox;
    private JCheckBox isScanXmlBox;
    private JCheckBox isScanParamMultipartBox;

    private JCheckBox isScanNullParameterBox;

    private JCheckBox isStartRemoteCmdExtensionBox;

    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader) {
        JPanel baseSetting = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.yamlReader = yamlReader;

        this.input1_1(baseSetting, c);
        this.input1_2(baseSetting, c);

        this.input2_1(baseSetting, c);
        this.input2_2(baseSetting, c);
        this.input2_3(baseSetting, c);
        this.input2_4(baseSetting, c);
        this.input2_5(baseSetting, c);
        this.input2_6(baseSetting, c);
        this.input2_7(baseSetting, c);
        this.input2_8(baseSetting, c);

        this.input3_1(baseSetting, c);
        this.input3_2(baseSetting, c);

        tabs.addTab("基本设置", baseSetting);
    }

    private void input1_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_1_1 = new JLabel("基础设置");
        br_lbl_1_1.setForeground(new Color(255, 89, 18));
        br_lbl_1_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_1_1.getFont().getSize() + 2));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 1;
        baseSetting.add(br_lbl_1_1, c);
    }

    private void input1_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartBox = new JCheckBox("插件-启动", this.yamlReader.getBoolean("isStart"));
        this.isStartBox.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 2;
        baseSetting.add(this.isStartBox, c);
    }

    private void input2_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_2_1 = new JLabel("扫描类型设置");
        br_lbl_2_1.setForeground(new Color(255, 89, 18));
        br_lbl_2_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_2_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 3;
        baseSetting.add(br_lbl_2_1, c);
    }

    private void input2_2(JPanel baseSetting, GridBagConstraints c) {
        this.isScanGetBox = new JCheckBox("扫描GET类型参数", this.yamlReader.getBoolean("scan.type.isScanGet"));
        this.isScanGetBox.setFont(new Font("Serif", Font.PLAIN, this.isScanGetBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 4;
        baseSetting.add(this.isScanGetBox, c);
    }

    private void input2_3(JPanel baseSetting, GridBagConstraints c) {
        this.isScanPostBox = new JCheckBox("扫描POST类型参数", this.yamlReader.getBoolean("scan.type.isScanPost"));
        this.isScanPostBox.setFont(new Font("Serif", Font.PLAIN, this.isScanPostBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 5;
        baseSetting.add(this.isScanPostBox, c);
    }

    private void input2_4(JPanel baseSetting, GridBagConstraints c) {
        this.isScanCookieBox = new JCheckBox("扫描Cookie类型参数", this.yamlReader.getBoolean("scan.type.isScanCookie"));
        this.isScanCookieBox.setFont(new Font("Serif", Font.PLAIN, this.isScanCookieBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 6;
        baseSetting.add(this.isScanCookieBox, c);
    }


    private void input2_5(JPanel baseSetting, GridBagConstraints c) {
        this.isScanJsonBox = new JCheckBox("扫描JSON类型参数", this.yamlReader.getBoolean("scan.type.isScanJson"));
        this.isScanJsonBox.setFont(new Font("Serif", Font.PLAIN, this.isScanJsonBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 7;
        baseSetting.add(this.isScanJsonBox, c);
    }

    private void input2_6(JPanel baseSetting, GridBagConstraints c) {
        this.isScanXmlBox = new JCheckBox("扫描Xml类型参数", this.yamlReader.getBoolean("scan.type.isScanXml"));
        this.isScanXmlBox.setFont(new Font("Serif", Font.PLAIN, this.isScanXmlBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 8;
        baseSetting.add(this.isScanXmlBox, c);
    }

    private void input2_7(JPanel baseSetting, GridBagConstraints c) {
        this.isScanParamMultipartBox = new JCheckBox("扫描ParamMultipart(例如上传文件的名称)", this.yamlReader.getBoolean("scan.type.isScanParamMultipart"));
        this.isScanParamMultipartBox.setFont(new Font("Serif", Font.PLAIN, this.isScanParamMultipartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 9;
        baseSetting.add(this.isScanParamMultipartBox, c);
    }

    private void input2_8(JPanel baseSetting, GridBagConstraints c) {
        this.isScanNullParameterBox = new JCheckBox("扫描空参数请求", this.yamlReader.getBoolean("scan.type.isScanNullParameter"));
        this.isScanNullParameterBox.setFont(new Font("Serif", Font.PLAIN, this.isScanNullParameterBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 10;
        baseSetting.add(this.isScanNullParameterBox, c);
    }

    private void input3_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_3_1 = new JLabel("应用程序配置");
        br_lbl_3_1.setForeground(new Color(255, 89, 18));
        br_lbl_3_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_3_1.getFont().getSize() + 2));
        c.insets = new Insets(15, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 11;
        baseSetting.add(br_lbl_3_1, c);
    }

    private void input3_2(JPanel baseSetting, GridBagConstraints c) {
        this.isStartRemoteCmdExtensionBox = new JCheckBox("远程命令扩展-启动", this.yamlReader.getBoolean("application.remoteCmdExtension.config.isStart"));
        this.isStartRemoteCmdExtensionBox.setFont(new Font("Serif", Font.PLAIN, this.isStartRemoteCmdExtensionBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 12;
        baseSetting.add(this.isStartRemoteCmdExtensionBox, c);
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }

    /**
     * 获取允许运行插入点类型列表
     * 0 = GET, 1 = POST, 2 = COOKIE, 6 = JSON, 3/4 = XML, PARAM_MULTIPART_ATTR = 5
     *
     * @return
     */
    public List<Integer> getScanTypeList() {
        List<Integer> typeList = new ArrayList<Integer>();

        if (this.isScanGetBox.isSelected()) {
            typeList.add(0);
        }

        if (this.isScanPostBox.isSelected()) {
            typeList.add(1);
        }

        if (this.isScanCookieBox.isSelected()) {
            typeList.add(2);
        }

        if (this.isScanJsonBox.isSelected()) {
            typeList.add(6);
        }

        if (this.isScanXmlBox.isSelected()) {
            typeList.add(3);
            typeList.add(4);
        }

        if (this.isScanParamMultipartBox.isSelected()) {
            typeList.add(5);
        }

        return typeList;
    }

    public List<String> getBlackListParameters() {
        return this.yamlReader.getStringList("blackListParameters");
    }

    public Boolean isStartRemoteCmdExtension() {
        return this.isStartRemoteCmdExtensionBox.isSelected();
    }

    public Boolean isScanNullParameter() {
        return this.isScanNullParameterBox.isSelected();
    }
}