package burp.Bootstrap;

import burp.*;
import burp.Ui.Tags;

import java.util.List;
import java.util.ArrayList;

public class BurpAnalyzedRequest {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private CustomBurpHelpers customBurpHelpers;

    private IHttpRequestResponse requestResponse;

    private List<IParameter> eligibleParameters = new ArrayList<>();

    private Tags tags;

    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, Tags tags, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();

        this.tags = tags;

        this.customBurpHelpers = new CustomBurpHelpers(callbacks);

        this.requestResponse = requestResponse;

        initEligibleParameters();
    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }

    /**
     * 初始化所有符合条件的参数
     */
    private void initEligibleParameters() {
        List<Integer> scanTypeList = this.tags.getBaseSettingTagClass().getScanTypeList();

        List<String> blackListParameters = this.tags.getBaseSettingTagClass().getBlackListParameters();

        if (!analyzeRequest().getParameters().isEmpty()) {
            if (blackListParameters == null || blackListParameters.size() <= 0) {
                for (IParameter p : analyzeRequest().getParameters()) {
                    for (Integer type : scanTypeList) {
                        if (p.getType() == type) {
                            this.eligibleParameters.add(p);
                        }
                    }
                }
            } else {
                for (IParameter p : analyzeRequest().getParameters()) {
                    for (Integer type : scanTypeList) {
                        String name = p.getName().trim();
                        if (!CustomHelpers.listKeyExists(name, blackListParameters) && Integer.valueOf(p.getType()).equals(type)) {
                            this.eligibleParameters.add(p);
                        }
                    }
                }
            }
        }

        // 空参数可以进行扫描时,添加一个GET参数作为标志符
        Boolean isScanNullParameter = this.tags.getBaseSettingTagClass().isScanNullParameter();
        if (this.eligibleParameters.size() <= 0 && isScanNullParameter) {
            this.eligibleParameters.add(this.helpers.buildParameter("headerTest", "test", (byte) 0));
        }
    }

    /**
     * 获取所有符合条件的json参数
     *
     * @return List<IParameter>
     */
    public List<IParameter> getEligibleParameters() {
        return this.eligibleParameters;
    }

    /**
     * 判断站点是否有符合条件的参数
     *
     * @return
     */
    public Boolean isSiteEligibleParameters() {
        if (this.getEligibleParameters().size() > 0) {
            return true;
        }

        return false;
    }

    /**
     * 会根据程序类型自动组装请求的 请求发送接口
     *
     * @param p
     * @param payload
     * @param headers
     * @return
     */
    public IHttpRequestResponse makeHttpRequest(IParameter p, String payload, List<String> headers) {
        byte[] newRequest;

        // headers头处理
        List<String> newHeaders = new ArrayList<>();
        if (headers != null && headers.size() != 0) {
            for (String h : this.analyzeRequest().getHeaders()) {
                if (!CustomHelpers.listKeySearch(h.split(": ")[0] + ": ", headers)) {
                    newHeaders.add(h);
                }
            }
            newHeaders.addAll(headers);
        } else {
            newHeaders = this.analyzeRequest().getHeaders();
        }

        // 数据处理
        if (p.getType() == 0 || p.getType() == 1 || p.getType() == 2) {
            // 数据为,GET,POST,COOKIE时的处理
            newRequest = this.buildBaseParameter(p, payload, newHeaders);
        } else {
            // 其它数据格式请求处理方法
            newRequest = this.buildHttpMessage(p, payload, newHeaders);
        }

        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(), newRequest);
        return newHttpRequestResponse;
    }

    /**
     * 普通数据格式的请求处理方法
     *
     * @param p
     * @param payload
     * @param headers
     * @return
     */
    private byte[] buildBaseParameter(IParameter p, String payload, List<String> headers) {
        byte[] request = this.requestResponse().getRequest();
        String requestBody = this.customBurpHelpers.getHttpRequestBody(request);

        // 添加header头
        byte[] newRequest = this.helpers.buildHttpMessage(headers, requestBody.getBytes());

        IParameter newParameter = this.helpers.buildParameter(p.getName(), payload, p.getType());

        return this.helpers.updateParameter(newRequest, newParameter);
    }

    /**
     * 其它数据格式请求处理方法
     *
     * @param p
     * @param payload
     * @param headers
     * @return
     */
    private byte[] buildHttpMessage(IParameter p, String payload, List<String> headers) {
        byte[] request = this.requestResponse().getRequest();
        request = CustomHelpers.substringReplace(new String(request), p.getValueStart(), p.getValueEnd(), payload).getBytes();
        String requestBody = this.customBurpHelpers.getHttpRequestBody(request);
        byte[] newRequest = this.helpers.buildHttpMessage(headers, requestBody.getBytes());
        return newRequest;
    }
}