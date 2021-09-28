package org.fiware.cybercaptor.server.remediation.cost;

import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.json.JSONObject;

import java.io.*;

// A class to replace CyberCAPTOR's OperationalCostParameters.
public class RemediationCostParameters {
    public final String costParameterFilename = "operational-cost-params.json";
    private final int DEFAULT_COST = 1;

    private int patch = this.DEFAULT_COST;
    private int firewall = this.DEFAULT_COST;

    public RemediationCostParameters() {
        // For now no error checking will be performed.
        // As this object is used by the Monitoring object
        // and exceptions should not happen at all.
        // If they do, this object will fall back to its defaults.
        // This isn't concerning as the module will receive the correct values
        // later by the profiling service.
        try {
            this.loadFromDisk();
        }
        // Also remember to create a new file.
        catch (IOException e) {
            e.printStackTrace();

            try { this.saveToDisk(); }
            catch (IOException f) { f.printStackTrace(); }
        }
        catch (IllegalArgumentException e) {
            e.printStackTrace();

            try { this.saveToDisk(); }
            catch (IOException f) { f.printStackTrace(); }
        }
    }

    public void saveToDisk() throws IOException {
        // Get the correct path for the file.
        String path = ProjectProperties.getProperty("cost-parameters-path");
        path += "/" + costParameterFilename;

        // Prepare the JSON object to save.
        JSONObject costObject = new JSONObject();
        costObject.put("patch", this.patch);
        costObject.put("firewall", this.firewall);

        // Save the JSON object to file.
        String jsonString = costObject.toString();
        BufferedWriter writer = new BufferedWriter(new FileWriter(path));
        writer.write(jsonString);
        writer.close();
    }

    public void loadFromDisk() throws FileNotFoundException, IOException, IllegalArgumentException {
        // Get the correct path for the file.
        String path = ProjectProperties.getProperty("cost-parameters-path");
        path += "/" + costParameterFilename;

        // Get the JSON object from the file.
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String jsonString = "", line;
        while ((line = reader.readLine()) != null) {
            jsonString += line;
        }

        // Load the JSON object ...
        JSONObject costObject = new JSONObject(jsonString);
        // ... and its parameters to memory.
        this.setPatchCost(costObject.getInt("patch"));
        this.setFirewallCost(costObject.getInt("firewall"));
    }

    public int getPatchCost() {
        return patch;
    }

    public int getFirewallCost() {
        return firewall;
    }

    public void setPatchCost(int patch) throws IllegalArgumentException {
        if ((patch >= 1) && (patch <= 5)) {
            this.patch = patch;
        }
        else {
            throw new IllegalArgumentException("The cost parameter must be in the range [1, 5].");
        }
    }

    public void setFirewallCost(int firewall) throws IllegalArgumentException {
        if ((firewall >= 1) && (firewall <= 5)) {
            this.firewall = firewall;
        }
        else {
            throw new IllegalArgumentException("The cost parameter must be in the range [1, 5].");
        }
    }
}
