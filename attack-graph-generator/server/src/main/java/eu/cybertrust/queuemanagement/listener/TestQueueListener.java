package eu.cybertrust.queuemanagement.listener;

//import org.junit.jupiter.api.Test;

import eu.cybertrust.queuemanagement.*;
import eu.cybertrust.queuemanagement.TopicSubscriptionManager;

//import static org.junit.jupiter.api.Assertions.assertEquals;



public class TestQueueListener {
	//@Test
	public void subscribe() {
		final String URI = "tcp://iridanos.sdbs.uop.gr:61616?jms.userName=system&jms.password=managerXcybertrust";
		final String testURI = "tcp://172.16.10:61613?jms.userName=cybertrust&jms.password=ctispbus12!@";
		final String topic ="Response.Mitigation";
		
		MessageConsumer mc = new MessageConsumer("");
		try {
			TopicSubscriptionManager.subscribeTo(testURI, topic, mc);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			Thread.sleep(400);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
