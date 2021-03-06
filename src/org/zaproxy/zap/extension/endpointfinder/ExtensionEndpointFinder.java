/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.endpointfinder;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyByteHttpPanelViewModel;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelDefaultViewSelectorFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionEndpointFinder extends ExtensionAdaptor {
    public static final String NAME = "ExtensionEndpointFinder";

    public ExtensionEndpointFinder() {
        super(NAME);
    }
    
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        
        if (getView() != null) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();

            panelManager.addResponseViewFactory(ResponseSplitComponent.NAME, new ResponseEndpointFinderTextViewFactory());
            panelManager.addResponseDefaultViewSelectorFactory(ResponseSplitComponent.NAME, new ResponseEndpointFinderTextViewDefaultViewSelectorFactory());
        }
    }
    
    public boolean canUnload() {
        return true;
    }
    
    public void unload() {
        if (getView() != null) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();

            panelManager.removeResponseViewFactory(ResponseSplitComponent.NAME, ResponseEndpointFinderTextViewFactory.NAME);
            panelManager.removeResponseViews(ResponseSplitComponent.NAME, ResponseEndpointFinderTextView.NAME, ResponseSplitComponent.ViewComponent.BODY);
            
            panelManager.removeResponseDefaultViewSelectorFactory(ResponseSplitComponent.NAME, ResponseEndpointFinderTextViewDefaultViewSelectorFactory.NAME);
            panelManager.removeResponseDefaultViewSelectors(ResponseSplitComponent.NAME, ResponseEndpointFinderTextViewDefaultViewSelector.NAME, ResponseSplitComponent.ViewComponent.BODY);
        }
    }
    
    private static final class ResponseEndpointFinderTextViewFactory implements HttpPanelViewFactory {
        public static final String NAME = "ResponseEndpointFinderTextViewFactory";
        
        public String getName() {
            return NAME;
        }

        public HttpPanelView getNewView() {
            return new ResponseEndpointFinderTextView(new ResponseBodyByteHttpPanelViewModel());
        }
        
        public Object getOptions() {
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }

    private static final class ResponseEndpointFinderTextViewDefaultViewSelector implements HttpPanelDefaultViewSelector {
        public static final String NAME = "ResponseEndpointFinderTextViewDefaultViewSelector";
        
        public String getName() {
            return NAME;
        }
        
        public boolean matchToDefaultView(Message message) {
        	return ResponseEndpointFinderTextView.isJavaScriptContent(message);
        }

        public String getViewName() {
            return ResponseEndpointFinderTextView.NAME;
        }

        public int getOrder() {
            return 20;
        }
    }

    private static final class ResponseEndpointFinderTextViewDefaultViewSelectorFactory implements HttpPanelDefaultViewSelectorFactory {
        private static HttpPanelDefaultViewSelector defaultViewSelector = null;
        public static final String NAME = "ResponseEndpointFinderTextViewDefaultViewSelectorFactory";
        
        private HttpPanelDefaultViewSelector getDefaultViewSelector() {
            if (defaultViewSelector == null) {
                createViewSelector();
            }
            return defaultViewSelector;
        }

        private synchronized void createViewSelector() {
            if (defaultViewSelector == null) {
                defaultViewSelector = new ResponseEndpointFinderTextViewDefaultViewSelector();
            }
        }
        
        public String getName() {
            return NAME;
        }
        
        public HttpPanelDefaultViewSelector getNewDefaultViewSelector() {
            return getDefaultViewSelector();
        }
        
        public Object getOptions() {
        	System.out.println("Get Options ...");
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }
    
    public String getAuthor() {
        return "Olivier Arteau";
    }
}
