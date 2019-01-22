/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.endpointfinder;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.AbstractHttpByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyByteHttpPanelViewModel;

import ca.zhack.endpointfinder.EndpointEntry;
import ca.zhack.endpointfinder.EndpointFinder;
import ca.zhack.endpointfinder.EndpointResult;
import ca.zhack.endpointfinder.Position;

/**
 * @author Olivier Arteau
 */
public class ResponseEndpointFinderTextView implements HttpPanelView, HttpPanelViewModelListener {
	public static final String NAME = "ResponseEndpointFinderTextView";
	
	private JPanel mainPanel;
    private JLabel resultLabel;
    
    private AbstractHttpByteHttpPanelViewModel model;

    public ResponseEndpointFinderTextView(ResponseBodyByteHttpPanelViewModel model) {
        this.model = model;

        resultLabel = new JLabel();
        resultLabel.setVerticalAlignment(JLabel.TOP);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(new JScrollPane(resultLabel));

        this.model.addHttpPanelViewModelListener(this);
    }

    public void setSelected(boolean selected) {
        if (selected) {
            resultLabel.requestFocusInWindow();
        }
    }

    public String getCaptionName() {
        return "EndpointFinder";
    }

    public String getTargetViewName() {
        return "";
    }

    public int getPosition() {
        return 1;
    }

    public boolean isEnabled(Message message) {
    	return isJavaScriptContent(message);
    }

    public boolean hasChanged() {
        return false;
    }

    public JComponent getPane() {
        return mainPanel;
    }

    public boolean isEditable() {
        return false;
    }
    
    public String getName() {
        return NAME;
    }

    public HttpPanelViewModel getModel() {
        return model;
    }
    
    public void dataChanged(HttpPanelViewModelEvent e) {
        if (!isEnabled(model.getMessage())) {
            resultLabel.setText("");
            return;
        }

        try {
        	HttpMessage msg = (HttpMessage) model.getMessage();
        	String stringToParse = new String(msg.getResponseBody().getBytes());
        	StringBuilder display = new StringBuilder();
        	EndpointResult result = EndpointFinder.getEndpoints(stringToParse);
        	List<EndpointEntry> entries = result.getEntries();
        	
        	display.append("<html>");
        	display.append("Results (" + entries.size() + ")<br /><br />");
        	
        	for (EndpointEntry entry : entries) {
        		display.append("--------------------<br />");
        		display.append("Path : " + entry.getPath() + "<br />");
        		
        		
        		if (entry.getUnknownPosition().size() > 0) {
        			int positionNumber = 1;
        			for (Position pos : entry.getUnknownPosition()) {
        				String formatUnknowInfo = "Variable #%d : %s (start: %d, end: %d)<br />";
        				display.append(String.format(
        						formatUnknowInfo, 
        						positionNumber, 
        						stringToParse.substring(pos.getStart(), pos.getEnd()),
        						pos.getStart(),
        						pos.getEnd()
        				));
        			}
        		}
        	}
        	
        	display.append("--------------------<br /><br />");
        	display.append("</html>");
        	resultLabel.setText(display.toString());
        } catch (Exception err) {
        	String errMessage = "An error occured during the parsing of the content.\n\n";
        	errMessage += err.getMessage();
        	resultLabel.setText(errMessage);
        }
    }
    
    public static boolean isJavaScriptContent(Message message) {
    	if (!(message instanceof HttpMessage)) {
            return false;
        }

        for (HttpHeaderField field : ((HttpMessage) message).getResponseHeader().getHeaders()) {
        	if (field.getName().toLowerCase().equals("content-type")) {
        		return field.getValue().contains("javascript");
        	}
        }
        
        return false;
    }
    
    public void setEditable(boolean editable) {   }
    public void setParentConfigurationKey(String configurationKey) { }
    public void loadConfiguration(FileConfiguration fileConfiguration) { }
    public void saveConfiguration(FileConfiguration fileConfiguration) { }
    public void save() { }
}
