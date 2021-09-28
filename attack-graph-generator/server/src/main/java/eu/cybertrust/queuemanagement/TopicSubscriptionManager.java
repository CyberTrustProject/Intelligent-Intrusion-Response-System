package eu.cybertrust.queuemanagement;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.Session;
import javax.jms.Topic;
 
import org.apache.activemq.ActiveMQConnectionFactory;

import java.util.HashMap;
import java.util.Collection;

public class TopicSubscriptionManager {

	private static class ConnectionInfo {
		Connection c;
		Session s;
		HashMap<String, MessageConsumer> topic2Consumer = new HashMap<String, MessageConsumer>();
	}
	
	private static HashMap<String, ConnectionInfo> openConnections = new HashMap<String, ConnectionInfo>();
	
	/*
	 * Subscribe to a topic at a specific URI. The topic must not have an active subscription by the same client.
	 * Upon reception of a message from the topic, the method onMessage(Message m) of the handler will be invoked.
	 * The filter parameter may specify a JMS filter according to the https://activemq.apache.org/selectors.html 
	 * specification (c.f. also https://timjansen.github.io/jarfiller/guide/jms/selectors.xhtml)
	 */
	public static void subscribeTo(String URI, String topic, MessageHandler handler, String filter) throws Exception {
		ConnectionInfo conInfo = openConnections.get(URI);
		if (conInfo == null) {
			ConnectionFactory cf = new ActiveMQConnectionFactory("failover://" + URI + "&wireFormat.maxInactivityDuration=0");
			conInfo = new ConnectionInfo();
			try {
				conInfo.c = cf.createConnection();
				conInfo.s =conInfo.c.createSession(false, Session.AUTO_ACKNOWLEDGE);
//				conInfo.c.setExceptionListener(new TopicSubscriptionExceptionListener(URI));
				conInfo.c.start();
				openConnections.put(URI, conInfo);
			} 
			catch (JMSException e) {
				throw new Exception(e.getMessage(), e.getCause());
			}
		}
		Topic topicObj = conInfo.s.createTopic(topic);
		MessageConsumer mc = conInfo.topic2Consumer.get(topic);
		if (mc != null) {
			throw new Exception("Topic " + topic + "at URI " + URI + " is already subscribed to by listener " + ((MessageHandler)(mc.getMessageListener())).getName());
		}
		
		MessageConsumer consumer1;
		if (filter == null)
			consumer1 = conInfo.s.createConsumer(topicObj);
		else
			consumer1 = conInfo.s.createConsumer(topicObj, filter);
		consumer1.setMessageListener(handler);
		conInfo.topic2Consumer.put(URI, consumer1);
	}
	
	public static void subscribeTo(String URI, String topic, MessageHandler handler) throws Exception {
		subscribeTo(URI, topic, handler, null);
	}
	
	public static boolean isListening(String URI, String topic) {
		ConnectionInfo conInfo = openConnections.get(URI);
		if (conInfo == null)
			return false;

		if (conInfo.topic2Consumer.containsKey(topic)) {
			return true;
		}
		return false;
	}
	
	public static void stopListening(String URI, String topic) throws Exception {
		ConnectionInfo conInfo = openConnections.get(URI);
		if (conInfo != null) {
			MessageConsumer mc = conInfo.topic2Consumer.get(topic);
			if (mc != null ) {
				mc.close();
				conInfo.topic2Consumer.remove(topic);
				if (conInfo.topic2Consumer.isEmpty()) {
					conInfo.s.close();
					conInfo.c.close();
					openConnections.remove(URI);
				}
			}
		}
		throw new Exception("Topic " + topic + " at URI " + URI + " is not subscribed to.");
	}
	
	public static Collection<String> getAllURIs() {
		return openConnections.keySet();
	}
	
	public static Collection<String> getAllTopics(String URI) throws Exception {
		ConnectionInfo conInfo = openConnections.get(URI);
		if (conInfo == null) {
			throw new Exception("No subscriptions to URI " + URI + " are registered.");
		}
		return conInfo.topic2Consumer.keySet();
	}
	
	public static void shutdownAll(String URI) throws Exception {
		ConnectionInfo conInfo = openConnections.get(URI);
		if (conInfo == null) {
			throw new Exception("No subscriptions to URI " + URI + " are registered.");
		}
		for (MessageConsumer mc: conInfo.topic2Consumer.values()) {
			mc.close();
		}
		conInfo.s.close();
		conInfo.c.close();
		openConnections.remove(URI);
	}
	
	public static void shutdownAll() throws Exception {
		for (String URI: openConnections.keySet())
			shutdownAll(URI);
	}
}
