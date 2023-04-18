package burp.Bootstrap;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.yaml.snakeyaml.Yaml;

import burp.IBurpExtenderCallbacks;

public class YamlReader {
    private static YamlReader instance;

    private static Map<String, Map<String, Object>> properties = new HashMap<>();

    private YamlReader(IBurpExtenderCallbacks callbacks) throws IOException {
        CustomBurpHelpers customBurpHelpers = new CustomBurpHelpers(callbacks);
        Path p = customBurpHelpers.getExtensionFilePath().resolve("resources/config.yml");
        File f = new File(p.toString());
        properties = new Yaml().load(Files.newInputStream(f.toPath()));
    }

    public static synchronized YamlReader getInstance(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            try {
                instance = new YamlReader(callbacks);
            } catch (IOException e) {
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            }
        }
        return instance;
    }

    /**
     * 获取yaml属性
     * 可通过 "." 循环调用
     * 例如这样调用: YamlReader.getInstance().getValueByKey("a.b.c.d")
     *
     * @param key
     * @return
     */
    public Object getValueByKey(String key) {
        String separator = ".";
        String[] separatorKeys = null;
        if (key.contains(separator)) {
            separatorKeys = key.split("\\.");
        } else {
            return properties.get(key);
        }
        Map<String, Map<String, Object>> finalValue = new HashMap<>();
        for (int i = 0; i < separatorKeys.length - 1; i++) {
            if (i == 0) {
                finalValue = (Map) properties.get(separatorKeys[i]);
                continue;
            }
            if (finalValue == null) {
                break;
            }
            finalValue = (Map) finalValue.get(separatorKeys[i]);
        }
        return finalValue == null ? null : finalValue.get(separatorKeys[separatorKeys.length - 1]);
    }

    public String getString(String key) {
        return String.valueOf(this.getValueByKey(key));
    }

    public String getString(String key, String defaultValue) {
        if (null == this.getValueByKey(key)) {
            return defaultValue;
        }
        return String.valueOf(this.getValueByKey(key));
    }

    public Boolean getBoolean(String key) {
        return (boolean) this.getValueByKey(key);
    }

    public Integer getInteger(String key) {
        return (Integer) this.getValueByKey(key);
    }

    public double getDouble(String key) {
        return (double) this.getValueByKey(key);
    }

    public List<String> getStringList(String key) {
        return (List<String>) this.getValueByKey(key);
    }

    public LinkedHashMap<String, Boolean> getLinkedHashMap(String key) {
        return (LinkedHashMap<String, Boolean>) this.getValueByKey(key);
    }
}