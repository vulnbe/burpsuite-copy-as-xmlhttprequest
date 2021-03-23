package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
    private static IExtensionHelpers helpers;
    private final static String pluginName = "Copy as XMLHttpRequest";
    private final static Set<String> forbiddenHeaders = new HashSet<String>(Arrays.asList(
            "host", "origin", "connection", "referer", "accept-encoding", "cookie", "content-length"));

    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName (pluginName);
        helpers = callbacks.getHelpers();
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return null;
        }
        JMenuItem menuItem = new JMenuItem(pluginName);
        menuItem.addActionListener(e -> processMessages(messages));
        return Collections.singletonList(menuItem);
    }

    private void processMessages(IHttpRequestResponse[] messages) {
        StringBuilder xhrCode = new StringBuilder();
        for (int i = messages.length - 1; i >= 0; i--) {
            IHttpRequestResponse message = messages[i];
            IRequestInfo ri = helpers.analyzeRequest(message);

            byte[] request = message.getRequest();
            int bodyOffset = ri.getBodyOffset();

            String funName = "XMLHttpReq";
            List<String> headers = ri.getHeaders();
            xhrCode.append("function ")
                    .append(funName).append(i)
                    .append("(e){\n")
                    .append("  console.log(e);\n")
                    .append("  var req = new XMLHttpRequest();\n")
                    .append("  req.onload = ");
            if (i != messages.length - 1 && i >= 0){
                xhrCode.append(funName).append(i+1);
            } else {
                xhrCode.append("console.log");
            }

            xhrCode.append(";\n")
                    .append("  req.open(`")
                    .append(ri.getMethod())
                    .append("`, `")
                    .append(ri.getUrl().toString())
                    .append("`);\n");

            Map<String,String> headersMap = filterHeaders(headers);
            for (Map.Entry<String, String> header : headersMap.entrySet()) {
                xhrCode.append("  req.setRequestHeader(`")
                        .append(escapeString(header.getKey()))
                        .append("`, `")
                        .append(escapeString(header.getValue()))
                        .append("`);\n");
            }

            xhrCode.append("  req.send(`")
                    .append(encodeBody(request, bodyOffset))
                    .append("`);\n")
                    .append("}\n");
            if (i == 0){
                xhrCode.append(funName).append(i).append("(`Sending first request...`);\n");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(xhrCode.toString()), this);
    }

    private Map<String,String> filterHeaders(List<String> rawHeaders){
        Map<String,String> headers = new HashMap<>();
        for (String rawHeader : rawHeaders) {
            if (rawHeader.indexOf(": ") == -1) continue;
            String[] hSplit = rawHeader.split(": ", 2);
            if (forbiddenHeaders.contains(hSplit[0].toLowerCase())) continue;
            headers.put(hSplit[0], hSplit[1]);
        }
        return headers;
    }

    private String encodeBody(byte[] bytes, int bodyOffset){
        ByteArrayOutputStream bb = new ByteArrayOutputStream();
        for (int i = bodyOffset; i < bytes.length; i++){
            bb.write(bytes[i]);
        }
        return escapeString(helpers.bytesToString(bb.toByteArray()));
    }

    private String escapeString(String inputString){
        return inputString
                .replace("\\","\\x5c")
                .replace("`","\\x60");
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {
    }
}

