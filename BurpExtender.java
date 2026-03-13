import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IExtensionStateListener;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IParameter;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITab;

import javax.swing.JSplitPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import java.awt.Component;
import java.awt.Dimension;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender, ITab, IProxyListener, IExtensionStateListener, IMessageEditorController {
    private static final String PAYLOAD_SUFFIX = "\"<>abc";

    private final Set<String> scannedKeys = ConcurrentHashMap.newKeySet();
    private final List<Finding> findings = new CopyOnWriteArrayList<Finding>();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private XssTableModel tableModel;
    private JSplitPane uiComponent;
    private JTable findingsTable;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private volatile Finding selectedFinding;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.tableModel = new XssTableModel(findings);

        callbacks.setExtensionName("History Reflected XSS Checker");
        callbacks.registerProxyListener(this);
        callbacks.registerExtensionStateListener(this);

        findingsTable = new JTable(tableModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(520);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(220);
        findingsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent event) {
                if (!event.getValueIsAdjusting()) {
                    showSelectedFinding();
                }
            }
        });

        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);

        JSplitPane messagePane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.getComponent(),
                responseViewer.getComponent()
        );
        messagePane.setResizeWeight(0.5d);

        uiComponent = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(findingsTable),
                messagePane
        );
        uiComponent.setPreferredSize(new Dimension(900, 560));
        uiComponent.setResizeWeight(0.35d);

        callbacks.customizeUiComponent(findingsTable);
        callbacks.customizeUiComponent(messagePane);
        callbacks.customizeUiComponent(uiComponent);
        callbacks.addSuiteTab(this);
        callbacks.printOutput("History Reflected XSS Checker loaded.");

        for (IHttpRequestResponse historyItem : callbacks.getProxyHistory()) {
            processHistoryItem(historyItem);
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            return;
        }

        processHistoryItem(message.getMessageInfo());
    }

    private void processHistoryItem(IHttpRequestResponse messageInfo) {
        byte[] request = messageInfo.getRequest();
        byte[] response = messageInfo.getResponse();
        if (request == null || response == null) {
            return;
        }

        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        if (!"GET".equalsIgnoreCase(requestInfo.getMethod())) {
            return;
        }

        if (!isTextHtmlResponse(response)) {
            return;
        }

        List<IParameter> urlParameters = getUrlParameters(requestInfo);
        if (urlParameters.isEmpty()) {
            return;
        }

        final String dedupKey = buildDedupKey(requestInfo, urlParameters);
        if (!scannedKeys.add(dedupKey)) {
            return;
        }

        final String originalUrl = requestInfo.getUrl().toString();
        final IHttpService httpService = messageInfo.getHttpService();
        final byte[] originalRequest = request;

        executor.submit(new Runnable() {
            @Override
            public void run() {
                scanRequest(httpService, originalRequest, originalUrl, urlParameters);
            }
        });
    }

    private void scanRequest(IHttpService httpService, byte[] originalRequest, String originalUrl, List<IParameter> urlParameters) {
        ProbeResult probeResult = mutateUrlParameters(originalRequest, urlParameters);
        IHttpRequestResponse probeResponse = callbacks.makeHttpRequest(httpService, probeResult.request);
        if (probeResponse == null) {
            return;
        }

        List<String> vulnerableParameters = findReflectedParameters(probeResponse.getResponse(), probeResult.parameterPayloads);
        if (vulnerableParameters.isEmpty()) {
            return;
        }

        addFinding(new Finding(
                originalUrl,
                joinParameters(vulnerableParameters),
                httpService,
                probeResult.request,
                probeResponse.getResponse()
        ));
    }

    private ProbeResult mutateUrlParameters(byte[] originalRequest, List<IParameter> urlParameters) {
        byte[] updatedRequest = originalRequest;
        List<ParameterPayload> parameterPayloads = new ArrayList<ParameterPayload>();
        for (int i = 0; i < urlParameters.size(); i++) {
            IParameter parameter = urlParameters.get(i);
            String payload = buildPayload(i + 1);
            IParameter newParameter = helpers.buildParameter(parameter.getName(), payload, IParameter.PARAM_URL);
            updatedRequest = helpers.updateParameter(updatedRequest, newParameter);
            parameterPayloads.add(new ParameterPayload(parameter.getName(), payload));
        }
        return new ProbeResult(updatedRequest, parameterPayloads);
    }

    private List<IParameter> getUrlParameters(IRequestInfo requestInfo) {
        List<IParameter> parameters = new ArrayList<IParameter>();
        for (IParameter parameter : requestInfo.getParameters()) {
            if (parameter.getType() == IParameter.PARAM_URL) {
                parameters.add(parameter);
            }
        }
        return parameters;
    }

    private List<String> findReflectedParameters(byte[] response, List<ParameterPayload> parameterPayloads) {
        List<String> vulnerableParameters = new ArrayList<String>();
        if (!isTextHtmlResponse(response)) {
            return vulnerableParameters;
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        String responseText = helpers.bytesToString(response);
        String body = responseText.substring(responseInfo.getBodyOffset());
        for (ParameterPayload parameterPayload : parameterPayloads) {
            if (body.contains(parameterPayload.payload)) {
                vulnerableParameters.add(parameterPayload.name);
            }
        }
        return vulnerableParameters;
    }

    private boolean isTextHtmlResponse(byte[] response) {
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        for (String header : responseInfo.getHeaders()) {
            int colonIndex = header.indexOf(':');
            if (colonIndex <= 0) {
                continue;
            }

            String name = header.substring(0, colonIndex).trim();
            if (!"content-type".equalsIgnoreCase(name)) {
                continue;
            }

            String value = header.substring(colonIndex + 1).trim().toLowerCase(Locale.ROOT);
            return value.contains("text/html");
        }
        return false;
    }

    private String buildDedupKey(IRequestInfo requestInfo, List<IParameter> urlParameters) {
        URL url = requestInfo.getUrl();
        List<String> names = new ArrayList<String>();
        for (IParameter parameter : urlParameters) {
            names.add(parameter.getName());
        }
        Collections.sort(names);

        StringBuilder builder = new StringBuilder();
        builder.append(requestInfo.getMethod()).append(' ');
        builder.append(url.getProtocol()).append("://").append(url.getHost());
        if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
            builder.append(':').append(url.getPort());
        }
        builder.append(url.getPath()).append('?');
        for (String name : names) {
            builder.append(name).append('&');
        }
        return builder.toString();
    }

    private String joinParameters(List<String> parameters) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < parameters.size(); i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(parameters.get(i));
        }
        return builder.toString();
    }

    private void addFinding(final Finding finding) {
        for (Finding existing : findings) {
            if (existing.url.equals(finding.url)) {
                return;
            }
        }
        findings.add(finding);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                tableModel.fireTableDataChanged();
                if (findings.size() == 1) {
                    findingsTable.setRowSelectionInterval(0, 0);
                }
            }
        });
    }

    private void showSelectedFinding() {
        int selectedRow = findingsTable.getSelectedRow();
        if (selectedRow < 0) {
            selectedFinding = null;
            requestViewer.setMessage(new byte[0], true);
            responseViewer.setMessage(new byte[0], false);
            return;
        }

        int modelRow = findingsTable.convertRowIndexToModel(selectedRow);
        selectedFinding = findings.get(modelRow);
        requestViewer.setMessage(selectedFinding.request, true);
        responseViewer.setMessage(selectedFinding.response, false);
    }

    private String buildPayload(int index) {
        return String.format(Locale.ROOT, "%03d%s", index, PAYLOAD_SUFFIX);
    }

    @Override
    public String getTabCaption() {
        return "Reflected XSS";
    }

    @Override
    public Component getUiComponent() {
        return uiComponent;
    }

    @Override
    public void extensionUnloaded() {
        executor.shutdownNow();
    }

    @Override
    public IHttpService getHttpService() {
        return selectedFinding == null ? null : selectedFinding.httpService;
    }

    @Override
    public byte[] getRequest() {
        return selectedFinding == null ? null : selectedFinding.request;
    }

    @Override
    public byte[] getResponse() {
        return selectedFinding == null ? null : selectedFinding.response;
    }

    private static final class Finding {
        private final String url;
        private final String vulnerableParameters;
        private final IHttpService httpService;
        private final byte[] request;
        private final byte[] response;

        private Finding(String url, String vulnerableParameters, IHttpService httpService, byte[] request, byte[] response) {
            this.url = url;
            this.vulnerableParameters = vulnerableParameters;
            this.httpService = httpService;
            this.request = request;
            this.response = response;
        }
    }

    private static final class ProbeResult {
        private final byte[] request;
        private final List<ParameterPayload> parameterPayloads;

        private ProbeResult(byte[] request, List<ParameterPayload> parameterPayloads) {
            this.request = request;
            this.parameterPayloads = parameterPayloads;
        }
    }

    private static final class ParameterPayload {
        private final String name;
        private final String payload;

        private ParameterPayload(String name, String payload) {
            this.name = name;
            this.payload = payload;
        }
    }

    private static final class XssTableModel extends AbstractTableModel {
        private final List<Finding> findings;

        private XssTableModel(List<Finding> findings) {
            this.findings = findings;
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public String getColumnName(int column) {
            if (column == 0) {
                return "URL";
            }
            return "Vulnerable Parameter";
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Finding finding = findings.get(rowIndex);
            if (columnIndex == 0) {
                return finding.url;
            }
            return finding.vulnerableParameters;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }
    }
}
