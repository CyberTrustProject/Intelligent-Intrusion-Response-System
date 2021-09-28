package eu.cybertrust.queuemanagement.listener;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

import eu.cybertrust.queuemanagement.MessageHandler;
 

public class MessageConsumer implements MessageHandler {

	   private String consumerName;
	    public MessageConsumer(String consumerName) {
	        this.consumerName = consumerName;
	    }
	 
	    public String getName() {return consumerName;}
	    
	    public void onMessage(Message message) {
	        TextMessage textMessage = (TextMessage) message;
	        try {
	            System.out.println(consumerName + " received " + textMessage.getText());
	        } catch (JMSException e) {          
	            e.printStackTrace();
	        }
	    }
}
