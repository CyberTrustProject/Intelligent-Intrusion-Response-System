package eu.cybertrust.queuemanagement;

import javax.jms.ExceptionListener;
import javax.jms.JMSException;

public class TopicSubscriptionExceptionListener implements ExceptionListener {
    volatile JMSException e;
    private String URI;

    public TopicSubscriptionExceptionListener(String URI) {
        this.URI = URI;
    }

    @Override
    public void onException(JMSException e) {
        this.e = e;

        System.out.println("==========================================================");
        System.out.println(e.getMessage());
        System.out.println(this.URI);
    }
}
