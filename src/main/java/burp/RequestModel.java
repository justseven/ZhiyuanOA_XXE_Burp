package burp;

import java.net.URL;
import java.util.List;

public class RequestModel {
    URL target;

    public void setTarget(URL target) {
        this.target = target;
    }

    public void setHeaders(List<String> headers) {
        Headers = headers;
    }

    public void setDateBytes(byte[] dateBytes) {
        this.dateBytes = dateBytes;
    }

    List<String> Headers;

    byte[] dateBytes;

    public List<String> getHeaders() {
        return Headers;
    }

    public byte[] getDateBytes() {
        return dateBytes;
    }
    public URL getTarget() {
        return target;
    }
}
