package org.fiware.cybercaptor.server.system.integrationbus;

import eu.cybertrust.queuemanagement.MessageHandler;
import org.fiware.cybercaptor.server.rest.RestApplication;

import javax.jms.Message;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;

public class GenericMessageConsumer implements MessageHandler {
    // Constants.
    private final String baseURL = "http://127.0.0.1:8080/ag-engine-server/rest/json/v2";
    private final int connectionTimeout = 5 * 1000;
    // Internal REST call settings and variables.
    private String restCall = "";
    private String restMethod = "";
    private String restResponse = "";
    // Bus settings.
    private String topic = "";
    // Internal variables.
    private String fullRestCallURL = "";

    @Override
    public void onMessage(Message message) {
        // REMEMBER!
        // Each consumer should implement its own onMessage()
        // and its own getName().
    }

    public GenericMessageConsumer(String topic, String method, String call) {
        this.setTopic(topic);
        this.setRestMethod(method);
        this.setRestCall(call);
    }

    public Integer performGET() throws Exception {
        Integer HTTPresponse = 0;

        // Prepare the base connection settings.
        URL irgConnectionURL = new URL(this.fullRestCallURL);
        HttpURLConnection conn = (HttpURLConnection) irgConnectionURL.openConnection();
        conn.setRequestMethod(this.restMethod);
        conn.setConnectTimeout(this.connectionTimeout);
        conn.setDoInput(true);
        conn.setRequestProperty("Accept", "application/json");

        // Get the response.
        HTTPresponse = conn.getResponseCode();
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String tmp = "";
        while ((tmp = rd.readLine()) != null) {
            this.restResponse += tmp;
        }

        // Print the response.
        //System.out.println("RESPONSE: " + this.restResponse);

        conn.disconnect();
        return HTTPresponse;
    }

    public Integer performPOST(String payload) throws Exception {
        Integer HTTPresponse = 0;

        // Prepare the base connection settings.
        URL irgConnectionURL = new URL(this.fullRestCallURL);
        HttpURLConnection conn = (HttpURLConnection) irgConnectionURL.openConnection();
        conn.setRequestMethod(this.restMethod);
        conn.setConnectTimeout(this.connectionTimeout);
        conn.setDoInput(true);
        conn.setRequestProperty("Accept", "application/json");

        // POST-specific base connection settings.
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");

        // Send the request.
        DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
        wr.write(payload.getBytes());
        HTTPresponse = conn.getResponseCode();
        RestApplication.print_message(Level.INFO, "Payload sent: " + HTTPresponse);

        // Get the response.
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String tmp = "";
        while ((tmp = rd.readLine()) != null) {
            this.restResponse += tmp;
        }

        // Print the response.
        //System.out.println("RESPONSE: " + this.restResponse);

        conn.disconnect();
        return HTTPresponse;
    }

    @Override
    public String getName() {
        // REMEMBER: Override this for every new consumer.
        return "DEFAULT_NAME";
    }

    public String getRestCall() {
        return restCall;
    }

    public void setRestCall(String call) {
        if (call.startsWith("/")) {
            this.restCall = call;
        }
        else {
            this.restCall = "/" + call;
        }

        this.fullRestCallURL = this.baseURL + this.restCall;
    }

    public String getRestMethod() {
        return restMethod;
    }

    public void setRestMethod(String method) throws IllegalArgumentException {
        if (method.toUpperCase().equals("GET") || method.toUpperCase().equals("POST")) {
            this.restMethod = method.toUpperCase();
        }
        else {
            throw new IllegalArgumentException("The method must be either GET or POST.");
        }
    }

    public String getBaseURL() {
        return baseURL;
    }

    public String getFullRestCallURL() {
        return fullRestCallURL;
    }

    public void setTopic(String topic) {
        if (topic.isEmpty() || (topic == null)) {
            throw new IllegalArgumentException("The topic should not be empty or null.");
        }
        else {
            this.topic = topic;
        }
    }

    public String getTopic() {
        return topic;
    }

    public String getRestResponse() {
        return restResponse;
    }
}
