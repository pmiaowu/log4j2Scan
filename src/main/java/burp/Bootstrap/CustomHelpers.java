package burp.Bootstrap;

import java.util.*;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;

public class CustomHelpers {
    /**
     * 随机取若干个字符
     *
     * @param number
     * @return String
     */
    public static String randomStr(int number) {
        StringBuffer s = new StringBuffer();
        char[] stringArray = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6',
                '7', '8', '9'};
        Random random = new Random();
        for (int i = 0; i < number; i++) {
            char num = stringArray[random.nextInt(stringArray.length)];
            s.append(num);
        }
        return s.toString();
    }

    /**
     * 获取精确到秒的时间戳
     *
     * @param date
     * @return Integer
     */
    public static Integer getSecondTimestamp(Date date) {
        if (null == date) {
            return 0;
        }
        String timestamp = String.valueOf(date.getTime() / 1000);
        return Integer.valueOf(timestamp);
    }

    /**
     * 判断某个List中是否存在指定的key
     * 注意: 大小写不区分
     * 如果该 key 存在, 则返回 true, 否则返回 false。
     *
     * @param val1 规定要查找的字符串
     * @param l1   规定要搜索的List
     * @return
     */
    public static Boolean listKeyExists(String val1, List<String> l1) {
        for (String s : l1) {
            if (s.toLowerCase().equals(val1.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断某个List中是否搜索的到指定的key
     * 注意: 大小写不区分
     * 如果该 key 存在, 则返回 true, 否则返回 false。
     *
     * @param val1 规定要查找的字符串
     * @param l1   规定要搜索的List
     * @return
     */
    public static Boolean listKeySearch(String val1, List<String> l1) {
        for (String s : l1) {
            if (s.toLowerCase().contains(val1.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取参数数据
     * 例如:
     * getParam("token=xx;Identifier=xxx;", "token"); 返回: xx
     *
     * @param d         被查找的数据
     * @param paramName 要查找的字段
     * @return
     */
    public static String getParam(final String d, final String paramName) {
        if (d == null || d.length() == 0)
            return null;

        String value = "test=test;" + d;

        final int length = value.length();
        int start = value.indexOf(';') + 1;
        if (start == 0 || start == length)
            return null;

        int end = value.indexOf(';', start);
        if (end == -1)
            end = length;

        while (start < end) {
            int nameEnd = value.indexOf('=', start);
            if (nameEnd != -1 && nameEnd < end
                    && paramName.equals(value.substring(start, nameEnd).trim())) {
                String paramValue = value.substring(nameEnd + 1, end).trim();
                int valueLength = paramValue.length();
                if (valueLength != 0)
                    if (valueLength > 2 && '"' == paramValue.charAt(0)
                            && '"' == paramValue.charAt(valueLength - 1))
                        return paramValue.substring(1, valueLength - 1);
                    else
                        return paramValue;
            }

            start = end + 1;
            end = value.indexOf(';', start);
            if (end == -1)
                end = length;
        }

        return null;
    }

    /**
     * 字符串截取替换
     *
     * @param val1 原字符串
     * @param val2 偏移值的开头位置
     * @param val3 偏移值的结束位置
     * @param val4 要替换的值
     * @return
     */
    public static String substringReplace(String val1, int val2, int val3, String val4) {
        return val1.substring(0, val2) + val4 + val1.substring(val3);
    }

    /**
     * 判断是否为json
     *
     * @param str
     * @return
     */
    public static boolean isJson(String str) {
        // 防止被日,一定要开
        ParserConfig.getGlobalInstance().setSafeMode(true);
        str = str.trim();
        try {
            if (str == null || str.length() <= 0) {
                return false;
            }

            // 替换特殊字符,
            String randomStr = "$" + randomStr(20) + "$";
            str = str.replace("@", randomStr);
            JSONObject.parseObject(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * json字符串值替换
     * 该功能会递归将所有json的value替换成指定字符串
     *
     * @param var1 json字符串
     * @param var2 要被替换的内容
     * @return
     */
    public static String jsonStringValueReplace(String var1, String var2) {
        // 防止被日,一定要开
        ParserConfig.getGlobalInstance().setSafeMode(true);

        // 替换特殊字符,
        String randomStr = "$" + randomStr(20) + "$";
        var1 = var1.replace("@", randomStr);

        // 开始正式替换
        JSONObject jsonObject = JSONObject.parseObject(var1);
        for (String k : jsonObject.keySet()) {
            if (jsonObject.get(k) instanceof JSONArray) {
                JSONArray arr = JSONObject.parseArray(jsonObject.getString(k));
                for (int i = 0; i < arr.size(); i++) {
                    Object o = arr.get(i);
                    arr.set(i, jsonStringValueReplace(o.toString(), var2));
                }
                jsonObject.put(k, arr);
            } else {
                jsonObject.put(k, var2);
            }
        }

        // 返回,并且把前面的特殊字符,替换回来
        return jsonObject.toJSONString().replace(randomStr, "@");
    }
}