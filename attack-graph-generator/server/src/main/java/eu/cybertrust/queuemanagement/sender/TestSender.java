package eu.cybertrust.queuemanagement.sender;

import javax.jms.JMSException;

//import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import eu.cybertrust.busmessages.GenericMessage;
import eu.cybertrust.queuemanagement.*;

public class TestSender {
	//@Test
	public void testSendMessage() throws JMSException, Exception {
		//final String URI = "tcp://iridanos.sdbs.uop.gr:61616?jms.userName=system&jms.password=managerXcybertrust";
		final String URI = "tcp://172.16.10:61613?jms.userName=cybertrust&jms.password=ctispbus12!@";
		final String topic ="Response.Mitigation";		
				
		
		GenericMessage m = new GenericMessage();
		m.setSource("theSource");
		m.setMsgTopic("deviceListChange");
		m.setTimestamp(1574345078);
//		m.setSignatureAlg("this");
//		m.setSignatureSig("that");
		m.addPayloadField("deviceId", "deviceId");
		m.addPayloadField("changeType", "explicitAddition");
		m.addPayloadField("deviceOwner", "userId");
		String textMessage = m.toJSON();
		TopicMessageSender.sendTo(URI, topic, textMessage);
	}
}
