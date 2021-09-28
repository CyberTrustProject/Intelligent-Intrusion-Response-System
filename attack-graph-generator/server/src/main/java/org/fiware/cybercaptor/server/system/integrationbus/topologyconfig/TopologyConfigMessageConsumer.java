package org.fiware.cybercaptor.server.system.integrationbus.topologyconfig;

import org.fiware.cybercaptor.server.rest.RestApplication;
import org.fiware.cybercaptor.server.system.integrationbus.GenericMessageConsumer;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.TextMessage;
import java.util.logging.Level;

public class TopologyConfigMessageConsumer extends GenericMessageConsumer {
    private final String consumerName = "POST_topology_config";

    @Override
    public void onMessage(Message message) {
        TextMessage msg = (TextMessage) message;

        try {
            RestApplication.print_message(Level.INFO, this.consumerName + " recv: " + msg.getText());
            this.performPOST(msg.getText());
            RestApplication.print_message(Level.INFO, this.consumerName + " answ: " + this.getRestResponse());
            // Shall we post the response back to the bus?
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getName() {
        return this.consumerName;
    }

    public TopologyConfigMessageConsumer(String topic, String method, String call) {
        super(topic, method, call);
    }
}
