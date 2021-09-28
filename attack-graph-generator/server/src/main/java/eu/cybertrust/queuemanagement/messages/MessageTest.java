package eu.cybertrust.queuemanagement.messages;

//import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import eu.cybertrust.busmessages.*;

public class MessageTest {	
	//@Test
	public void testMessage() {
		GenericMessage m = new GenericMessage();
		m.setSource("theSource");
		m.setMsgTopic("deviceListChange");
		m.setTimestamp(1574345078);
//		m.setSignatureAlg("this");
//		m.setSignatureSig("that");
		m.addPayloadField("deviceId", "deviceId");
		m.addPayloadField("changeType", "explicitAddition");
		m.addPayloadField("deviceOwner", "userId");
		String stringRep = "";
		try {
			stringRep = m.toJSON();
			System.out.println(stringRep);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		
		try {
			GenericMessage m1 = GenericMessage.createMessageFromJSON(stringRep);
			System.out.println(m1.toJSON());
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
}
