package org.fiware.cybercaptor.server.properties;

import java.util.ArrayList;
import org.apache.commons.net.util.SubnetUtils;

public class ProtectedNetworks {
    private String[] ipAddresses;
    private ArrayList<SubnetUtils.SubnetInfo> networks = new ArrayList<SubnetUtils.SubnetInfo>();

    public ProtectedNetworks() {
        this.ipAddresses = ProjectProperties.getProperty("net-ip").split(",");
        for(String addr : this.ipAddresses) {
            SubnetUtils.SubnetInfo network = (new SubnetUtils(addr)).getInfo();
            this.networks.add(network);
        }
    }

    // This only works with one considered network range.
    public String gatewayAddress() {
        String[] allAddresses = this.networks.get(0).getAllAddresses();
        return allAddresses[0];
    }

    public void clearNetworks() {
        this.networks.clear();
    }

    public String toString() {
        String result = "";

        for (SubnetUtils.SubnetInfo network : this.networks) {
            result += network.getAddress() + " ";
        }

        return result;
    }

    public void addNetwork(String address) {
        SubnetUtils.SubnetInfo network = (new SubnetUtils(address)).getInfo();
        this.networks.add(network);
    }

    public boolean belongsToNetwork(String address) {
        for(SubnetUtils.SubnetInfo network : this.networks) {
            if(network.isInRange(address)) {
                return true;
            }
        }

        return false;
    }
}
