package burp.Bootstrap;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.file.Path;
import java.nio.file.Paths;

import burp.*;

public class CustomBurpHelpers {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public CustomBurpHelpers(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public Path getExtensionFilePath() {
        return Paths.get(this.callbacks.getExtensionFilename()).getParent();
    }

    /**
     * 获取请求的Body内容
     *
     * @return String
     */
    public String getHttpRequestBody(byte[] request) {
        IRequestInfo requestInfo = this.helpers.analyzeRequest(request);

        int httpRequestBodyOffset = requestInfo.getBodyOffset();
        int httpRequestBodyLength = request.length - httpRequestBodyOffset;

        String httpRequestBody = null;
        try {
            httpRequestBody = new String(request, httpRequestBodyOffset, httpRequestBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpRequestBody;
    }

    /**
     * 获取响应的Body内容
     *
     * @return String
     */
    public String getHttpResponseBody(byte[] response) {
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

        int httpResponseBodyOffset = responseInfo.getBodyOffset();
        int httpResponseBodyLength = response.length - httpResponseBodyOffset;

        String httpResponseBody = null;
        try {
            httpResponseBody = new String(response, httpResponseBodyOffset, httpResponseBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpResponseBody;
    }
}