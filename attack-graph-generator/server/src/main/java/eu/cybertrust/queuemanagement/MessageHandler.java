package eu.cybertrust.queuemanagement;

public interface MessageHandler extends javax.jms.MessageListener {
	public String getName();
}
