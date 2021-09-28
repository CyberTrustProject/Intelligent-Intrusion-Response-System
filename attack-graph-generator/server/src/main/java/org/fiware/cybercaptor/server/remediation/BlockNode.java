package org.fiware.cybercaptor.server.remediation;

import org.fiware.cybercaptor.server.attackgraph.Vertex;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.topology.asset.IPAddress;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.PortRange;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class BlockNode {
    public Vertex target;
    public InformationSystem informationSystem;
    public Set<Vertex> affectedNodes = new HashSet<Vertex>();
    public Expression root = new Expression();
    private boolean firstIteration = true;

    public BlockNode(Vertex target, InformationSystem informationSystem) {
        this.target = target;
        this.informationSystem = informationSystem;

        if (this.target.type == Vertex.VertexType.OR) {
            this.root.operator = ExpressionOperator.AND;
        } else if (this.target.type == Vertex.VertexType.AND) {
            this.root.operator = ExpressionOperator.OR;
        } else if (this.target.type == Vertex.VertexType.LEAF) {
            this.root.operator = ExpressionOperator.LEAF;
        } else {
            this.root.operator = ExpressionOperator.NONE;
        }
    }

    public class Solution {
        public Set<NetworkPair> rules = null;
        public Vertex target;
        public Set<Vertex> affectedNodes = new HashSet<Vertex>();
        public boolean addedToList = false;

        public Solution(Vertex target) {
            this.rules = new HashSet<NetworkPair>();
            this.target = target;
        }

        public Solution(Vertex target, ArrayList<NetworkPair> rules) {
            this.rules = new HashSet<NetworkPair>();
            this.target = target;

            for (NetworkPair rule : rules) {
                this.rules.add(rule);
            }
        }

        @Override
        public boolean equals(Object obj) {
            if ((obj == null) || (this.getClass() != obj.getClass())) {
                return false;
            }
            if (this == obj) {
                return true;
            }

            Solution other = (Solution) obj;
            return this.rules.equals(other.rules);
        }

        @Override
        public int hashCode() {
            int hash = 0;

            for (NetworkPair r : this.rules) {
                try {
                    for (String iptrables_rule : r.generateFirewallRule()) {
                        hash += iptrables_rule.hashCode();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            return hash;
        }
    }

    public class Expression {
        public ArrayList<Expression> expressions = new ArrayList<Expression>();
        public ArrayList<NetworkPair> networkPairs = new ArrayList<NetworkPair>();
        public ExpressionOperator operator = ExpressionOperator.NONE;

        @Override
        public String toString() {
            return operator.name() + ": " + expressions.size() + " expressions, " + networkPairs.size() + " network pairs.";
        }
    }

    public enum ExpressionOperator {
        AND, OR, LEAF, NONE
    }

    public class NetworkPair {
        public String from;
        public String to;
        public String protocol;
        public String port;
        public Vertex originatingVertex;
        private InformationSystem informationSystem;

        private String internetIP = "0.0.0.0";
        private String internetMask = "0.0.0.0";
        private String mask = "255.255.255.255";

        public NetworkPair(String from, String to, String protocol, String port, Vertex node, InformationSystem informationSystem) throws Exception {
            this.originatingVertex = node;
            this.from = from;
            this.to = to;
            this.protocol = protocol;
            this.port = port;
            this.informationSystem = informationSystem;
        }

        public String generatePfSenseRule() throws Exception {
            String rule = "easyrule block ";
            String netInterface = ProjectProperties.getProperty("pfsense-interface");

            rule += netInterface + " " + this.from;
            return rule;
        }

        public ArrayList<String> generateFirewallRule() throws Exception {
            ArrayList<String> result = new ArrayList<String>();

            if (this.from.equals("internet")) {
                FirewallRule ruleIn = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(internetIP), new IPAddress(internetMask), new PortRange(true),
                        new IPAddress(to), new IPAddress(mask), PortRange.fromString(this.port),
                        FirewallRule.Table.INPUT
                );

                FirewallRule ruleOut = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(internetIP), new IPAddress(internetMask), new PortRange(true),
                        new IPAddress(to), new IPAddress(mask), PortRange.fromString(this.port),
                        FirewallRule.Table.OUTPUT
                );

                result.add(ruleIn.toIptablesAddRule());
                result.add(ruleOut.toIptablesAddRule());

                return result;
            } else if (this.to.equals("internet")) {
                FirewallRule ruleIn = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(from), new IPAddress(mask), new PortRange(true),
                        new IPAddress(internetIP), new IPAddress(internetMask), PortRange.fromString(this.port),
                        FirewallRule.Table.INPUT
                );

                FirewallRule ruleOut = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(from), new IPAddress(mask), new PortRange(true),
                        new IPAddress(internetIP), new IPAddress(internetMask), PortRange.fromString(this.port),
                        FirewallRule.Table.OUTPUT
                );

                result.add(ruleIn.toIptablesAddRule());
                result.add(ruleOut.toIptablesAddRule());

                return result;
            } else {
                FirewallRule ruleIn = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(from), new IPAddress(mask), new PortRange(true),
                        new IPAddress(to), new IPAddress(mask), PortRange.fromString(this.port),
                        FirewallRule.Table.INPUT
                );

                FirewallRule ruleOut = new FirewallRule(FirewallRule.Action.DROP,
                        FirewallRule.Protocol.getProtocolFromString(this.protocol),
                        new IPAddress(from), new IPAddress(mask), new PortRange(true),
                        new IPAddress(to), new IPAddress(mask), PortRange.fromString(this.port),
                        FirewallRule.Table.OUTPUT
                );

                result.add(ruleIn.toIptablesAddRule());
                result.add(ruleOut.toIptablesAddRule());

                return result;
            }
        }

        @Override
        public boolean equals(Object obj) {
            if ((obj == null) || (this.getClass() != obj.getClass())) {
                return false;
            }
            if (this == obj) {
                return true;
            }

            NetworkPair other = (NetworkPair) obj;
            boolean matchIP = this.from.equals(other.from) && this.to.equals(other.to);
            boolean oppositeIP = this.from.equals(other.to) && this.to.equals(other.from);

            return matchIP || oppositeIP;
        }

        @Override
        public int hashCode() {
            return (this.from.hashCode() + this.to.hashCode());
        }

        @Override
        public String toString() {
            return protocol + ":" + port + " " + from + "->" + to + " VERTEX:" + originatingVertex.id + "/" + originatingVertex.type;
        }
    }
}