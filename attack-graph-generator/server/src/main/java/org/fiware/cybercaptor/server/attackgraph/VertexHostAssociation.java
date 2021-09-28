package org.fiware.cybercaptor.server.attackgraph;

import org.fiware.cybercaptor.server.attackgraph.fact.DatalogCommand;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.informationsystem.Service;

import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.component.FirewallRule;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class VertexHostAssociation {

    // Removes non-existent vertices from the association tables.
    public static void RefreshAssociationTables(AttackGraph attackGraph) {
        for (VertexList l : attackGraph.vertexToHostAssociations) {
            ArrayList<Vertex> toRemove = new ArrayList<Vertex>();

            for (Vertex v : l.vertices) {
                if (!attackGraph.vertices.values().contains(v))
                    toRemove.add(v);
            }

            l.vertices.removeAll(toRemove);
        }
    }

    public static ArrayList<VertexList> AssociateHostsToVertices(InformationSystem informationSystem, AttackGraph attackGraph) throws Exception {
        ArrayList<VertexList> lists = new ArrayList<VertexList>();

        // Get every host of the topology and make a list of every type for every combination.
        // All the information we need is in another structure, kept by InformationSystem,
        // but we need all hostnames of the topology.
        // We can get them from the Topology class.
        ArrayList<InformationSystemHost> hosts = new ArrayList<InformationSystemHost>();
        for (Host h : informationSystem.getTopology().getHosts()) {
            hosts.add(informationSystem.getHostByNameOrIPAddress(h.getName()));
        }

        for (InformationSystemHost h : hosts) {

            // IP_ONLY.
            for (Interface i : h.getInterfaces().values()) {
                if (!h.getId().isEmpty()) {
                    lists.add(new VertexList(h.getId(), i.getAddress().getAddress(), h.getName()));
                } else {
                    lists.add(new VertexList(i.getAddress().getAddress(), h.getName()));
                }
            }

            // FULL_INFO and PARTIAL_INFO
            if (!h.getServices().isEmpty()) {
                for (Service s : h.getServices().values()) {
                    // FULL_INFO.
                    if (!h.getId().isEmpty()) {
                        lists.add(new VertexList(h.getId(), s.getIpAddress().getAddress(), h.getName(), s.getPortNumber(), protocolToString(s.getProtocol()), s));
                    } else {
                        lists.add(new VertexList(s.getIpAddress().getAddress(), h.getName(), s.getPortNumber(), protocolToString(s.getProtocol()), s));
                    }

                    // PARTIAL_INFO, check if there's another IP/Port/Protocol combo.
                    boolean foundAnotherList = false;
                    for (VertexList l : lists) {
                        if (l.equals(s.getIpAddress().getAddress(), s.getPortNumber(), protocolToString(s.getProtocol()))) {
                            foundAnotherList = true;
                        }
                    }
                    if (!foundAnotherList) {
                        if (!h.getId().isEmpty()) {
                            lists.add(new VertexList(h.getId(), s.getIpAddress().getAddress(), h.getName(), s.getPortNumber(), protocolToString(s.getProtocol())));
                        } else {
                            lists.add(new VertexList(s.getIpAddress().getAddress(), h.getName(), s.getPortNumber(), protocolToString(s.getProtocol())));
                        }
                    }

                    // LIMITED_INFO.
                    foundAnotherList = false;
                    for (VertexList l : lists) {
                        if (l.equals(s.getIpAddress().getAddress(), s.getPortNumber())) {
                            foundAnotherList = true;
                        }
                    }
                    if (!foundAnotherList) {
                        if (!h.getId().isEmpty()) {
                            lists.add(new VertexList(h.getId(), s.getIpAddress().getAddress(), h.getName(), s.getPortNumber()));
                        } else {
                            lists.add(new VertexList(s.getIpAddress().getAddress(), h.getName(), s.getPortNumber()));
                        }
                    }
                }
            }
        }

        /*

        TODO: Add info from these rules.
        accessMaliciousInput
            informationSystem.existingMachineByNameOrIPAddress(command.params[0]);
        principalCompromised
            informationSystem.existingMachineByUserName(command.params[0]);
        accessFile
            informationSystem.existingMachineByNameOrIPAddress(command.params[0]);

        */

        // Move around the Attack Graph.
        for (Vertex v : attackGraph.vertices.values()) {
            // Not all Vertices have datalog facts. Especially AND nodes.
            if (v.fact != null) {
                if ((v.fact.type == Fact.FactType.DATALOG_FACT) && (v.fact.datalogCommand != null)) {
                    DatalogCommand command = v.fact.datalogCommand;

                    String ip = "";
                    int port = -1;
                    String protocol = "";
                    Service service = null;

                    if (command.command.equals("vulExists")) {
                        //*vulExists(_host, _vulID, _program)
                        // vulExists(_machine, _vulID, _program, _range, _consequence)
                        // vulExists('pfsense', 'CVE-2018-15919', 'openssh ssh', remoteExploit, privEscalation)

                        // Get the Host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if (s.getName().equals(command.params[2])) {
                                ip = s.getIpAddress().getAddress();
                                port = s.getPortNumber();
                                protocol = protocolToString(s.getProtocol());
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("haclprimit") || command.command.equals("hacl")) {
                        //*hacl(_src, _dst, _prot, _port)
                        // haclprimit(_src, _dst, _prot, _port)
                        // haclprimit('10.0.10.105','10.0.10.1', 9594,'TCP')

                        // Work on the Source IP.
                        ip = command.params[0];
                        port = Integer.parseInt(command.params[3]);
                        protocol = command.params[2];

                        // Try to see if we can associate it with a service
                        // Get the Host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(ip);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if ((s.getIpAddress().getAddress().equals(ip)) && (s.getPortNumber() == port) && (protocol.equals(protocolToString(s.getProtocol())))) {
                                service = s;
                                break;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }

                        // ---------------------------------------------------------------------------------------------

                        // Work on the Destination IP.
                        ip = command.params[1];

                        // Try to see if we can associate it with a service
                        // Get the Host.
                        host = informationSystem.getHostByNameOrIPAddress(ip);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if ((s.getIpAddress().getAddress().equals(ip)) && (s.getPortNumber() == port) && (protocol.equals(protocolToString(s.getProtocol())))) {
                                service = s;
                                break;
                            }
                        }

                        // Add to lists.
                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("attackerLocated")) {
                        //*attackerLocated(IP)
                        // attackerLocated(_host)
                        // attackerLocated('pfsense')

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        for (Interface i : host.getInterfaces().values()) {
                            ip = i.getAddress().getAddress();

                            for (VertexList l : lists) {
                                // Add to IP_ONLY list.
                                if (l.equals(ip)) {
                                    l.vertices.add(v);
                                }
                            }
                        }
                    } else if (command.command.equals("networkServiceInfo")) {
                        //*networkServiceInfo(_host, _program, _protocol, _port, _user)
                        // networkServiceInfo(_ip, _program, _protocol, _port, _user)
                        // networkServiceInfo('10.0.10.1', 'dnsmasq domain', 'TCP', 53, 'user')

                        ip = command.params[0];
                        port = Integer.parseInt(command.params[3]);
                        protocol = command.params[2];

                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if (s.getName().equals(command.params[1]) && (s.getPortNumber() == port) && protocolToString(s.getProtocol()).equals(protocol) && (s.getIpAddress().getAddress().equals(ip))) {
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("installed")) {
                        // installed(_h, _program)
                        // installed('pfsense','dnsmasq domain')

                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if (s.getName().equals(command.params[1])) {
                                ip = s.getIpAddress().getAddress();
                                port = s.getPortNumber();
                                protocol = protocolToString(s.getProtocol());
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("isInVlan")) {
                        // isInVlan(_ip,_vlan)
                        // isInVlan('1.1.1.1', 'internet')

                        ip = command.params[0];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("ipToVlan")) {
                        // ipToVlan(_ip,_vlan,_protocol,_port)
                        // ipToVlan('10.0.10.105','internet', 53,'TCP')

                        ip = command.params[0];
                        port = Integer.parseInt(command.params[2]);
                        protocol = command.params[3];

                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if (s.getName().equals(command.params[1]) && s.getIpAddress().getAddress().equals(ip) && (s.getPortNumber() == port) && protocolToString(s.getProtocol()).equals(protocol)) {
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("vlanToIP")) {
                        // vlanToIP(_vlan,_ip,_protocol,_port)
                        // vlanToIP('internet','10.0.10.105', 35009,'TCP')

                        ip = command.params[1];
                        port = Integer.parseInt(command.params[2]);
                        protocol = command.params[3];

                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        // Get the Services and find the relevant IP from it.
                        for (Service s : host.getServices().values()) {
                            if (s.getIpAddress().getAddress().equals(ip) && (s.getPortNumber() == port) && protocolToString(s.getProtocol()).equals(protocol)) {
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("defaultLocalFilteringBehavior")) {
                        // _behavior = allow/deny
                        // defaultLocalFilteringBehavior(_toip,_behavior)
                        // defaultLocalFilteringBehavior('internet_host',allow)
                        // defaultLocalFilteringBehavior(_,allow)

                        ip = command.params[0];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("hasIP")) {
                        // hasIP(_host,_IP)
                        // hasIP(internet_host,'1.1.1.1')

                        ip = command.params[1];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("execCode")) {
                        // execCode(_host, _user)
                        // execCode('pfsense', _)

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        for (Interface i : host.getInterfaces().values()) {
                            ip = i.getAddress().getAddress();

                            for (VertexList l : lists) {
                                // Add to IP_ONLY list.
                                if (l.equals(ip)) {
                                    l.vertices.add(v);
                                }
                            }
                        }
                    } else if (command.command.equals("hostAllowAccessToAllIP")) {
                        // hostAllowAccessToAllIP(?)
                        // hostAllowAccessToAllIP('Dmz-1')

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        for (Interface i : host.getInterfaces().values()) {
                            ip = i.getAddress().getAddress();

                            for (VertexList l : lists) {
                                // Add to IP_ONLY list.
                                if (l.equals(ip)) {
                                    l.vertices.add(v);
                                }
                            }
                        }
                    } else if (command.command.equals("hasAccount")) {
                        // hasAccount(_principal, _host, _account)

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[1]);
                        for (Interface i : host.getInterfaces().values()) {
                            ip = i.getAddress().getAddress();

                            for (VertexList l : lists) {
                                // Add to IP_ONLY list.
                                if (l.equals(ip)) {
                                    l.vertices.add(v);
                                }
                            }
                        }
                    } else if (command.command.equals("localAccessEnabled")) {
                        // localAccessEnabled(_ip, _fromIP, port)
                        // localAccessEnabled('10.0.10.105','10.0.10.1',port)
                        // NOTICE: 'port' is a keyword.

                        // Work on the Destination IP.
                        ip = command.params[0];

                        if (isNumber(command.params[2])) {
                            for (VertexList l : lists) {
                                port = Integer.parseInt(command.params[2]);
                                // Add to LIMITED_INFO list.
                                if (l.equals(ip, port)) {
                                    l.vertices.add(v);
                                }
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }

                        // ---------------------------------------------------------------------------------------------

                        // Work on the Source IP.
                        ip = command.params[1];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("localFilteringRule")) {
                        // localFilteringRule(_fromIP,_toIP,_port,_behavior)

                        // Work on the Source IP.
                        ip = command.params[0];
                        port = Integer.parseInt(command.params[2]);

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }

                        // ---------------------------------------------------------------------------------------------

                        // Work on the Destination IP.
                        ip = command.params[1];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("ipInSameVLAN")) {
                        // ipInSameVLAN(_ip1,_ip2)

                        // Work on the first IP.
                        ip = command.params[0];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }

                        // ---------------------------------------------------------------------------------------------

                        // Work on the second IP.
                        ip = command.params[1];

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("netAccess")) {
                        //*netAccess(_machine,_protocol,_port)
                        // netAccess(_ip,_protocol,_port)

                        port = Integer.parseInt(command.params[2]);
                        protocol = command.params[1];

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        for (Service s : host.getServices().values()) {
                            if ((s.getPortNumber() == port) && protocolToString(s.getProtocol()).equals(protocol)) {
                                ip = s.getIpAddress().getAddress();
                                service = s;
                            }
                        }

                        // Add to lists.
                        for (VertexList l : lists) {
                            // Add to FULL_INFO list.
                            if (l.equals(ip, port, protocol, service)) {
                                l.vertices.add(v);
                            }

                            // Add to PARTIAL_INFO list.
                            if (l.equals(ip, port, protocol)) {
                                l.vertices.add(v);
                            }

                            // Add to LIMITED_INFO list.
                            if (l.equals(ip, port)) {
                                l.vertices.add(v);
                            }

                            // Add to IP_ONLY list.
                            if (l.equals(ip)) {
                                l.vertices.add(v);
                            }
                        }
                    } else if (command.command.equals("canAccessHost")) {
                        // canAccessHost(_host)

                        // Get the host.
                        InformationSystemHost host = informationSystem.getHostByNameOrIPAddress(command.params[0]);
                        for (Interface i : host.getInterfaces().values()) {
                            ip = i.getAddress().getAddress();

                            for (VertexList l : lists) {
                                // Add to IP_ONLY list.
                                if (l.equals(ip)) {
                                    l.vertices.add(v);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also include relevant AND nodes for each OR/LEAF node added above.
        for (VertexList l : lists) {
            ArrayList<Vertex> toAdd = new ArrayList<Vertex>();

            for (Vertex v : l.vertices) {
                toAdd.addAll(addAffectedAndNodes(attackGraph, v));
            }

            l.vertices.addAll(toAdd);
        }

        // Remove empty lists.
        ArrayList<VertexHostAssociation.VertexList> listsToRemove = new ArrayList<>();
        for (VertexList l : lists) {
            if ((l.vertices == null) || (l.vertices.size() == 0)) {
                listsToRemove.add(l);
            }
        }
        lists.removeAll(listsToRemove);

        // Remove duplicate vertices from each list
        for (VertexList l : lists) {
            Set<Vertex> tmpSet = new HashSet<>(l.vertices);
            l.vertices.clear();
            l.vertices.addAll(tmpSet);
        }

        // debugPrintAllLists(lists);
        return lists;
    }

    private static ArrayList<Vertex> addAffectedAndNodes(AttackGraph attackGraph, Vertex vertex) {
        ArrayList<Vertex> result = new ArrayList<Vertex>();

        // Add the next AND nodes.
        for (Vertex p : vertex.children) {
            if (p.type == Vertex.VertexType.AND) {
                result.add(p);
            }
        }

        // System.out.println("    Vertex: " + vertex.id + " AND nodes: " + Arrays.toString(result.toArray()));
        return result;
    }

    private static boolean isNumber(String str) throws Exception {
        try {
            Integer.parseInt(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static String protocolToString(FirewallRule.Protocol protocol) {
        if (protocol == FirewallRule.Protocol.TCP) {
            return "TCP";
        } else if (protocol == FirewallRule.Protocol.UDP) {
            return "UDP";
        } else if (protocol == FirewallRule.Protocol.ICMP) {
            return "ICMP";
        } else if (protocol == FirewallRule.Protocol.ANY) {
            return "ANY";
        }

        return "NONE";
    }

    private static void debugPrintAllLists(ArrayList<VertexList> lists) {
        System.out.print("\n\n");

        for (VertexList l : lists) {
            if (!l.vertices.isEmpty()) {
                if (l.type == VertexListType.FULL_INFO) {
                    System.out.print("[FULL_INFO," + l.ip + ":" + l.port + "," + l.protocol + "," + l.service.getName() + "]: ");

                    for (Vertex v : l.vertices) {
                        System.out.print(v.id + " ");
                    }
                    System.out.print("\n");
                    for (Vertex v : l.vertices) {
                        System.out.println("    " + v.id + ": " + v.fact.factString);
                    }
                } else if (l.type == VertexListType.PARTIAL_INFO) {
                    System.out.print("[PARTIAL_INFO," + l.ip + ":" + l.port + "," + l.protocol + "]: ");

                    for (Vertex v : l.vertices) {
                        System.out.print(v.id + " ");
                    }
                    System.out.print("\n");
                    for (Vertex v : l.vertices) {
                        System.out.println("    " + v.id + ": " + v.fact.factString);
                    }
                } else if (l.type == VertexListType.LIMITED_INFO) {
                    System.out.print("[LIMITED_INFO," + l.ip + ":" + l.port + "]: ");

                    for (Vertex v : l.vertices) {
                        System.out.print(v.id + " ");
                    }
                    System.out.print("\n");
                    for (Vertex v : l.vertices) {
                        System.out.println("    " + v.id + ": " + v.fact.factString);
                    }
                } else {
                    System.out.print("[IP_ONLY," + l.ip + "]: ");

                    for (Vertex v : l.vertices) {
                        System.out.print(v.id + " ");
                    }
                    System.out.print("\n");
                    for (Vertex v : l.vertices) {
                        System.out.println("    " + v.id + ": " + v.fact.factString);
                    }
                }
            }
        }

        System.out.print("\n\n");
    }

    // Keeps a list of vertices that can be associated with a specific set of:
    // IP Address, Port, Protocol, and Service.
    //
    // Four types of specificity can be defined:
    //      (VertexListType = FULL_INFO) : IP Address, Port, Protocol, Service
    //   (VertexListType = PARTIAL_INFO) : IP Address, Port, Protocol
    //   (VertexListType = LIMITED_INFO) : IP Address, Port
    //        (VertexListType = IP_ONLY) : IP Address
    public static class VertexList implements Cloneable {
        public String ip;
        public String uuid = "";
        public String hostname;
        public int port;
        public String protocol;
        public Service service;
        public ArrayList<Vertex> vertices;
        public VertexListType type;

        @Override
        protected VertexList clone() throws CloneNotSupportedException {
            VertexList copy = null;

            if (this.type == VertexListType.FULL_INFO) {
                // IP|PORT|PROTOCOL|SERVICE
                copy = new VertexList(this.uuid, this.ip, this.hostname, this.port, this.protocol, this.service);
                copy.vertices.addAll(this.vertices);
            } else if (this.type == VertexListType.PARTIAL_INFO) {
                // IP|PORT|PROTOCOL
                copy = new VertexList(this.uuid, this.ip, this.hostname, this.port, this.protocol);
                copy.vertices.addAll(this.vertices);
            } else if (this.type == VertexListType.LIMITED_INFO) {
                // IP|PORT
                copy = new VertexList(this.uuid, this.ip, this.hostname, this.port);
                copy.vertices.addAll(this.vertices);
            } else if (this.type == VertexListType.IP_ONLY) {
                // IP
                copy = new VertexList(this.uuid, this.ip, this.hostname);
                copy.vertices.addAll(this.vertices);
            } else {
                throw new CloneNotSupportedException("The type of the VertexList is invalid.");
            }

            return copy;
        }

        public boolean equals(String ip, int port, String protocol, Service service) {
            if (this.type == VertexListType.FULL_INFO) {
                return (!this.ip.isEmpty()) &&
                        (!this.ip.equals("")) &&
                        (this.ip.equals(ip)) &&

                        (this.port != -1) &&
                        (this.port == port) &&

                        (!this.protocol.isEmpty()) &&
                        (!this.protocol.equals("")) &&
                        (!this.protocol.equals("NONE")) &&
                        (this.protocol.equals(protocol)) &&

                        (this.service != null) &&
                        (this.service.getName().equals(service.getName())) &&
                        (this.service.getIpAddress().getAddress().equals(service.getIpAddress().getAddress()));
            } else {
                return false;
            }
        }

        public boolean equals(String ip, int port, String protocol) {
            if (this.type == VertexListType.PARTIAL_INFO) {
                return (!this.ip.isEmpty()) &&
                        (!this.ip.equals("")) &&
                        (this.ip.equals(ip)) &&

                        (this.port != -1) &&
                        (this.port == port) &&

                        (!this.protocol.isEmpty()) &&
                        (!this.protocol.equals("")) &&
                        (!this.protocol.equals("NONE")) &&
                        (this.protocol.equals(protocol));
            } else {
                return false;
            }
        }

        public boolean equals(String ip, int port) {
            if (this.type == VertexListType.LIMITED_INFO) {
                return (!this.ip.isEmpty()) &&
                        (!this.ip.equals("")) &&
                        (this.ip.equals(ip)) &&

                        (this.port != -1) &&
                        (this.port == port);
            } else {
                return false;
            }
        }

        public boolean equals(String ip) {
            if (this.type == VertexListType.IP_ONLY) {
                return (!this.ip.isEmpty()) &&
                        (!this.ip.equals("")) &&
                        (this.ip.equals(ip));
            } else {
                return false;
            }
        }

        public VertexList(VertexListType type, String ip, String hostname, int port, String protocol, Service service) {
            this.ip = ip;
            this.hostname = hostname;
            this.port = port;
            this.protocol = protocol;
            this.service = service;

            this.type = type;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(VertexListType type, String uuid, String ip, String hostname, int port, String protocol, Service service) {
            this.ip = ip;
            this.uuid = uuid;
            this.hostname = hostname;
            this.port = port;
            this.protocol = protocol;
            this.service = service;

            this.type = type;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String ip, String hostname, int port, String protocol, Service service) {
            this.ip = ip;
            this.port = port;
            this.hostname = hostname;
            this.protocol = protocol;
            this.service = service;

            this.type = VertexListType.FULL_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String uuid, String ip, String hostname, int port, String protocol, Service service) {
            this.ip = ip;
            this.uuid = uuid;
            this.port = port;
            this.hostname = hostname;
            this.protocol = protocol;
            this.service = service;

            this.type = VertexListType.FULL_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String ip, String hostname, int port, String protocol) {
            this.ip = ip;
            this.port = port;
            this.protocol = protocol;
            this.hostname = hostname;

            this.type = VertexListType.PARTIAL_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String uuid, String ip, String hostname, int port, String protocol) {
            this.ip = ip;
            this.port = port;
            this.protocol = protocol;
            this.uuid = uuid;
            this.hostname = hostname;

            this.type = VertexListType.PARTIAL_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String ip, String hostname, int port) {
            this.ip = ip;
            this.port = port;
            this.hostname = hostname;

            this.type = VertexListType.LIMITED_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String uuid, String ip, String hostname, int port) {
            this.ip = ip;
            this.port = port;
            this.uuid = uuid;
            this.hostname = hostname;

            this.type = VertexListType.LIMITED_INFO;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String ip, String hostname) {
            this.ip = ip;
            this.hostname = hostname;

            this.type = VertexListType.IP_ONLY;
            this.vertices = new ArrayList<Vertex>();
        }

        public VertexList(String uuid, String ip, String hostname) {
            this.ip = ip;
            this.uuid = uuid;
            this.hostname = hostname;

            this.type = VertexListType.IP_ONLY;
            this.vertices = new ArrayList<Vertex>();
        }
    }

    public static enum VertexListType {
        // IP|PORT|PROTOCOL|SERVICE, IP|PORT|PROTOCOL, IP|PORT,      IP
        FULL_INFO, PARTIAL_INFO, LIMITED_INFO, IP_ONLY
    }
}
