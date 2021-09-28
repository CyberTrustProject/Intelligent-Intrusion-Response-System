package org.fiware.cybercaptor.server.rest;

import eu.cybertrust.queuemanagement.TopicMessageSender;
import eu.cybertrust.queuemanagement.TopicSubscriptionManager;
import org.apache.commons.io.IOUtils;
import org.fiware.cybercaptor.server.api.AttackPathManagement;
import org.fiware.cybercaptor.server.api.InformationSystemManagement;
import org.fiware.cybercaptor.server.attackgraph.*;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.informationsystem.InformationSystemHost;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.properties.ProtectedNetworks;
import org.fiware.cybercaptor.server.remediation.BlockNode;
import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.fiware.cybercaptor.server.remediation.cost.RemediationCostParameters;
import org.fiware.cybercaptor.server.rest.RestApplication.InternalTopicName;
import org.fiware.cybercaptor.server.rest.RestApplication.TopicName;
import org.fiware.cybercaptor.server.rest.RestApplication.ResultJSONStructureStatus;
import org.fiware.cybercaptor.server.system.LoggingHelperFunctions;
import org.fiware.cybercaptor.server.system.SystemInformation;
import org.fiware.cybercaptor.server.system.integrationbus.topologyconfig.TopologyConfigMessageConsumer;
import org.fiware.cybercaptor.server.topology.asset.Host;
import org.fiware.cybercaptor.server.topology.asset.component.Interface;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;

import java.io.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.jdom2.Element;

import java.net.URL;
import java.net.HttpURLConnection;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.lang.*;

// The final API to be used by the Cyber-Trust platform.
@Path("/json/v2/")
public class RestJsonAPIv2 {

    // curl http://127.0.0.1:10000/ag-engine-server/rest/json/v2/test
    @GET
    @Path("/system/test")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_system_test(@Context HttpServletRequest request) throws IOException, ClassNotFoundException {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/system/test, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.OK, "iRG test response.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/test, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/test, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/system/info")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_system_info(@Context HttpServletRequest request) throws IOException, ClassNotFoundException {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/system/info, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject payload = new JSONObject();

            // Get the SystemInfo object to retrieve its information.
            SystemInformation info = (SystemInformation) request.getSession(true).getServletContext().getAttribute("info");
            if (info == null) {
                info = new SystemInformation();
                request.getSession(true).getServletContext().setAttribute("info", info);
                Logger.getAnonymousLogger().info("The SystemInformation object didn't exist and was created.");
            }

            // Add initialization information.
            JSONObject init_info = new JSONObject();
            payload.put("initialized", init_info);
            init_info.put("state", info.getInitializedState());
            init_info.put("timestamp", info.getInitializedDate());

            // Also print this info to the logs for later reference.
            Logger.getAnonymousLogger().info("Initialized: State=" + info.getInitializedState() + ", Timestamp=" + info.getInitializedDate());

            JSONObject response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "iRG Server instance info successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/info, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/info, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/system/database/update")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_system_database_update(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/system/database/update, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject payload = new JSONObject();

            //Process p = Runtime.getRuntime().exec("python /root/remdb-misp/updateFromMisp.py");

            // Do stuff.
            // Check the following comment block on how to call the Python script.

            // If stuff fails use the following two lines to return an error.
            //      response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The remediation DB couldn't be updated.");
            //      return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);

            // If you want to add something to the response, use the payload object.
            // Else just ignore it, but don't delete it.

            JSONObject response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "iRG Server instance info successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/database/update, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/system/database/update, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/topology")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_topology(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        final String URI = ProjectProperties.getProperty("bus-uri");
        final String topic = TopicName.NETWORK_TOPOLOGY.getTopic();

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().warning("The monitoring object is empty, the system was not initialized.");
                response = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_TOPOLOGY, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            String xmlTopology = new XMLOutputter(Format.getCompactFormat()).outputString(monitoring.getInformationSystem().toDomXMLElement());
            payload.put("topology", xmlTopology);
            response = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_TOPOLOGY, payload, ResultJSONStructureStatus.OK, "Topology XML generated.");

            try {
                TopicMessageSender.sendTo(URI, topic, response.toString());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("[GET:/topology] Error when contacting the information bus: " + topic);
                e.printStackTrace();
            }

            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_TOPOLOGY, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/topology/config")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_topology_config(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().warning("The monitoring object is empty, the system was not initialized.");
                response = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            try {
                JSONObject irg = new JSONObject();
                payload.put("irg", irg);

                // Add the hosts list.
                JSONArray hosts = new JSONArray();
                irg.put("hosts", hosts);

                for (Host h : monitoring.getInformationSystem().getTopology().getHosts()) {
                    JSONObject host = new JSONObject();
                    hosts.put(host);

                    // Get the name and its UUID.
                    host.put("name", h.getName());
                    if (!h.getId().isEmpty()) {
                        host.put("id", h.getId());
                    }

                    // Get the security requirements.
                    InformationSystemHost informationSystemHost = monitoring.getInformationSystem().getHostByNameOrIPAddress(h.getName());
                    host.put("impact", informationSystemHost.getSecurityRequirements().get(0).getMetricPlainText());
                }

                // Add the cost structure.
                JSONObject costObject = new JSONObject();
                irg.put("cost", costObject);
                costObject.put("patch", monitoring.getRemediationCostParameters().getPatchCost());
                costObject.put("firewall", monitoring.getRemediationCostParameters().getFirewallCost());

                Integer HTTPresponse = 0;
                String ireResponseString = "";
                try {
                    // Contact the iRE and get its configuration.
                    String ireUrl = ProjectProperties.getProperty("ire-url-config");
                    URL ireConnectionUrl = new URL(ireUrl);
                    HttpURLConnection ireConnection = (HttpURLConnection) ireConnectionUrl.openConnection();
                    ireConnection.setDoInput(true);
                    ireConnection.setRequestProperty("Accept", "application/json");
                    ireConnection.setRequestMethod("GET");
                    // Set a connection timeout of 5 seconds.
                    ireConnection.setConnectTimeout(5 * 1000);
                    HTTPresponse = ireConnection.getResponseCode();

                    BufferedReader rd = new BufferedReader(new InputStreamReader(ireConnection.getInputStream()));
                    // Read the input
                    String tmpStr = "";
                    while ((tmpStr = rd.readLine()) != null) {
                        ireResponseString += tmpStr;
                    }

                    Logger.getAnonymousLogger().info("iRE configuration received: " + HTTPresponse);
                    if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                        Logger.getAnonymousLogger().info("Received: " + ireResponseString);
                    }

                    ireConnection.disconnect();
                } catch (Exception e) {
                    Logger.getAnonymousLogger().warning("Could not connect to the iRE: " + HTTPresponse);
                    e.printStackTrace();
                }

                if (HTTPresponse == 200) {
                    JSONObject ireResponse = new JSONObject(ireResponseString).getJSONObject("payload").getJSONObject("ire");
                    JSONObject ireObject = new JSONObject();

                    ireObject.put("auto_mode", ireResponse.getInt("auto_mode"));
                    ireObject.put("sa_tradeoff", ireResponse.getDouble("sa_tradeoff"));
                    ireObject.put("sp_tradeoff", ireResponse.getInt("sp_tradeoff"));

                    payload.put("ire", ireObject);
                }

            } catch (JSONException e) {
                Logger.getAnonymousLogger().severe("Could not retrieve the host configurations");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.ERROR, "Hosts configuration couldn't be retrieved.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.OK, "Hosts configuration was successfully retrieved.");

            final String URI = ProjectProperties.getProperty("bus-uri");
            final String topic = TopicName.SOHO_CONFIG.getTopic();
            try {
                TopicMessageSender.sendTo(URI, topic, response.toString());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("[GET:/topology/config] Error when contacting the information bus: " + topic);
                e.printStackTrace();
            }

            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/topology/config")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_config(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            Monitoring monitoring = (Monitoring) request.getSession().getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().warning("The monitoring object is empty, the system was not initialized.");
                response = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            try {
                JSONObject jsonInput = new JSONObject(jsonString);
                JSONObject inputPayload = jsonInput.getJSONObject("payload");
                String msg_id = jsonInput.getJSONObject("header").getString("msg_id");

                boolean uuid_updates = false;

                // Load the host list and their impact scores.
                if (inputPayload.has("irg")) {
                    JSONArray hosts = inputPayload.getJSONObject("irg").getJSONArray("hosts");
                    for (int i = 0; i < hosts.length(); i++) {
                        JSONObject host = hosts.getJSONObject(i);

                        if (host != null) {
                            // Get the host in the topology.
                            String hostname = host.getString("name");
                            InformationSystemHost informationSystemHost = monitoring.getInformationSystem().getHostByNameOrIPAddress(hostname);
                            if (informationSystemHost == null) {
                                throw new JSONException("");
                            }

                            // Set its parameters.
                            informationSystemHost.removeAllSecurityRequirements();
                            String impact = host.getString("impact");
                            SecurityRequirement requirement = new SecurityRequirement(
                                    impact,
                                    SecurityRequirement.getMetricValueFromPlainText(impact)
                            );
                            informationSystemHost.addSecurityRequirements(requirement);

                            // Check if it has a UUID.
                            if (host.has("id")) {
                                for (Host h : monitoring.getInformationSystem().getTopology().getHosts()) {
                                    if (h.getName().equals(hostname)) {
                                        h.setId(host.getString("id"));
                                        uuid_updates = true;
                                        break;
                                    }
                                }
                            }
                        } else {
                            Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                            throw new JSONException("");
                        }
                    }

                    // If UUID values were updated, refresh the vertex to host association tables.
                    if (uuid_updates) {
                        try {
                            AttackGraph attackGraph = monitoring.getAttackGraph();
                            attackGraph.vertexToHostAssociations = VertexHostAssociation.AssociateHostsToVertices(monitoring.getInformationSystem(), (MulvalAttackGraph) attackGraph);
                        } catch (Exception e) {
                            Logger.getAnonymousLogger().severe("Error during vertex UUID refresh");
                            e.printStackTrace();
                            throw e;
                        }
                    }

                    // Set the costs of the remediation actions.
                    JSONObject costs = inputPayload.getJSONObject("irg").getJSONObject("cost");
                    RemediationCostParameters params = monitoring.getRemediationCostParameters();
                    params.setPatchCost(costs.getInt("patch"));
                    params.setFirewallCost(costs.getInt("firewall"));
                }

                if (inputPayload.has("ire")) {

                    double sa_tradeoff = inputPayload.getJSONObject("ire").getDouble("sa_tradeoff");
                    System.out.println(" ~~~~~~~~~~~~~~~[TEST_SA] ~~~~~~~~~~~~" + sa_tradeoff);
                    request.getSession(true).getServletContext().setAttribute("sa_tradeoff", sa_tradeoff);

                    int sp_tradeoff = inputPayload.getJSONObject("ire").getInt("sp_tradeoff");
                    System.out.println(" ~~~~~~~~~~~~~~~[TEST_SP] ~~~~~~~~~~~~" + sp_tradeoff);
                    request.getSession(true).getServletContext().setAttribute("sp_tradeoff", sp_tradeoff);
                }

                double sa_tdoff = (double) request.getSession(true).getServletContext().getAttribute("sa_tradeoff");
                System.out.println("[SA_PARAM] ---> " + sa_tdoff);
            } catch (Exception e) {
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            response = RestApplication.prepareResponseJSONStructure(TopicName.SOHO_CONFIG, payload, ResultJSONStructureStatus.OK, "SOHO configuration loaded successfully.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/net-ip, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(RestApplication.TopicName.SOHO_CONFIG, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/config, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/topology/net-ip")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_netip(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/net-ip, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("net-ip.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            ProtectedNetworks protectedNetworks = new ProtectedNetworks();
            protectedNetworks.clearNetworks();
            ServletContext context = request.getSession().getServletContext();
            context.setAttribute("netip", protectedNetworks);

            try {
                JSONArray consideredNetworksJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < consideredNetworksJsonArray.length(); i++) {
                    String netAddr = consideredNetworksJsonArray.getString(i);
                    protectedNetworks.addNetwork(netAddr);
                }
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/net-ip, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The considered networks list has been successfully loaded.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/net-ip, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/net-ip, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/topology/vuln-scan-report")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_vulnscanreport(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/vuln-scan-report, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("vuln-scan-report.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare the initial OpenVAS XML structure.
            Element root_root = new Element("report");
            Element root = new Element("report");
            root_root.addContent(root);
            Element results = new Element("results");
            root.addContent(results);

            // Parse the JSON.
            JSONObject jsonReport;
            try {
                jsonReport = new JSONObject(jsonString);
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vuln-scan-report, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Convert the results to their OpenVAS equivalent.
            JSONArray hostList = jsonReport.getJSONArray("scan");
            for (int i = 0; i < hostList.length(); i++) {
                JSONObject hostObject = hostList.getJSONObject(i);

                // Get its IP address (always present).
                String hostString = hostObject.getJSONObject("addresses").getString("ipv4");

                // Add the services (name, port, vulns).
                if (hostObject.has("tcp")) {
                    JSONObject tcpPorts = hostObject.getJSONObject("tcp");

                    for (Object portKey : tcpPorts.keySet()) {
                        // Get the port number.
                        String portString = (String) portKey;
                        JSONObject portObj = tcpPorts.getJSONObject(portString);

                        // Prepare the service name.
                        String nameString = portObj.getString("product");
                        if (!nameString.isEmpty()) {
                            nameString += " ";
                        }
                        nameString += portObj.getString("name");

                        // Get the CPEs.
                        String cpeString = "";
                        String cpeVulnersString = "";
                        try {
                            cpeString = portObj.getString("cpe");
                        } catch (Exception e) {
                            Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no CPE information.");
                        }

                        // Get the CVEs.
                        ArrayList<String> cveList = new ArrayList<String>();
                        try {
                            String ftp_vsftpd_backdoor = portObj.getJSONObject("script").getString("ftp-vsftpd-backdoor");
                            String resultCVE = ftp_vsftpd_backdoor.split("\n")[4].trim().split("  ")[2].split(":")[1];
                            cveList.add(resultCVE);

                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info("Vuln: " + hostString + ":" + portString + " -> " + resultCVE);
                            }
                        } catch (JSONException e) {
                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no ftp-vsftpd-backdoor result.");
                            }
                        }
                        try {
                            // Check the report for vulners
                            String vulnersReport = portObj.getJSONObject("script").getString("vulners");
                            String[] resultList = vulnersReport.split("    ");

                            for (String s : resultList) {
                                String line = s.trim();

                                try {
                                    if (!line.isEmpty()) {
                                        if (!line.startsWith("cpe:/")) {
                                            String cve = line.split("\t")[0].trim();

                                            if (cve.contains(":")) {
                                                cve = cve.split(":")[1];
                                            }

                                            cveList.add(cve);

                                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                                Logger.getAnonymousLogger().info("Vuln: " + hostString + ":" + portString + " -> " + cve);
                                            }
                                        } else {
                                            cpeVulnersString = line;
                                        }
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    Logger.getAnonymousLogger().severe("Error when processing: " + line + " of " + hostString + ":" + portString);
                                }
                            }
                        } catch (JSONException e) {
                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no vulnerabilities.");
                            }
                        }

                        // Add the XML elements.
                        Element result = new Element("result");
                        results.addContent(result);

                        Element name = new Element("name");
                        name.setText(nameString);
                        result.addContent(name);

                        // Sort the CPEs
                        String hostCPE = "";
                        String serviceCPE = "";
                        if (!cpeString.isEmpty() && !cpeVulnersString.isEmpty() && !cpeString.equals(cpeVulnersString)) {
                            if (cpeString.contains("cpe:/a:")) {
                                serviceCPE = cpeString;
                            } else {
                                hostCPE = cpeString;
                            }

                            if (cpeVulnersString.contains("cpe:/a:")) {
                                serviceCPE = cpeVulnersString;
                            } else {
                                hostCPE = cpeVulnersString;
                            }
                        } else if (!cpeString.isEmpty()) {
                            if (cpeString.contains("cpe:/a:")) {
                                serviceCPE = cpeString;
                            } else {
                                hostCPE = cpeString;
                            }
                        }

                        Element hostCpeElement = new Element("host_cpe");
                        hostCpeElement.setText(hostCPE);
                        result.addContent(hostCpeElement);

                        Element serviceCpeElement = new Element("service_cpe");
                        serviceCpeElement.setText(serviceCPE);
                        result.addContent(serviceCpeElement);

                        Element host = new Element("host");
                        host.setText(hostString);
                        result.addContent(host);

                        Element port = new Element("port");
                        port.setText(portString + "/tcp");
                        result.addContent(port);

                        if (!cveList.isEmpty()) {
                            for (String cveString : cveList) {
                                Element nvt = new Element("nvt");
                                result.addContent(nvt);
                                Element cve = new Element("cve");
                                cve.setText(cveString);
                                nvt.addContent(cve);
                            }
                        }
                    }
                } else if (hostObject.has("udp")) {
                    JSONObject udpPorts = hostObject.getJSONObject("udp");

                    for (Object portKey : udpPorts.keySet()) {
                        // Get the port number.
                        String portString = (String) portKey;
                        JSONObject portObj = udpPorts.getJSONObject(portString);

                        // Prepare the service name.
                        String nameString = portObj.getString("product");
                        if (!nameString.isEmpty()) {
                            nameString += " ";
                        }
                        nameString += portObj.getString("name");

                        // Get the associated CPE.
                        String cpeString = "";
                        String cpeVulnersString = "";
                        try {
                            cpeString = portObj.getString("cpe");
                        } catch (Exception e) {
                            Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no CPE information.");
                        }

                        // Get the CVEs.
                        ArrayList<String> cveList = new ArrayList<String>();
                        try {
                            String ftp_vsftpd_backdoor = portObj.getJSONObject("script").getString("ftp-vsftpd-backdoor");
                            String resultCVE = ftp_vsftpd_backdoor.split("\n")[4].trim().split("  ")[2].split(":")[1];
                            cveList.add(resultCVE);

                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info("Vuln: " + hostString + ":" + portString + " -> " + resultCVE);
                            }
                        } catch (JSONException e) {
                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no ftp-vsftpd-backdoor result.");
                            }
                        }
                        try {
                            String vulnersReport = portObj.getJSONObject("script").getString("vulners");
                            String[] resultList = vulnersReport.split("    ");

                            for (String s : resultList) {
                                String line = s.trim();
                                if (!line.isEmpty()) {
                                    if (!line.startsWith("cpe:/")) {
                                        String cve = line.split("\t")[0].trim();
                                        cveList.add(cve);

                                        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                            Logger.getAnonymousLogger().info("Vuln: " + hostString + ":" + portString + " -> " + cve);
                                        }
                                    } else {
                                        cpeVulnersString = line;
                                    }
                                }
                            }
                        } catch (JSONException e) {
                            if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                                Logger.getAnonymousLogger().info(hostString + ":" + portString + " has no vulnerabilities.");
                            }
                        }

                        // Add the XML elements.
                        Element result = new Element("result");
                        results.addContent(result);

                        Element name = new Element("name");
                        name.setText(nameString);
                        result.addContent(name);

                        // Sort the CPEs
                        String hostCPE = "";
                        String serviceCPE = "";
                        if (!cpeString.isEmpty() && !cpeVulnersString.isEmpty() && !cpeString.equals(cpeVulnersString)) {
                            if (cpeString.contains("cpe:/a:")) {
                                serviceCPE = cpeString;
                            } else {
                                hostCPE = cpeString;
                            }

                            if (cpeVulnersString.contains("cpe:/a:")) {
                                serviceCPE = cpeVulnersString;
                            } else {
                                hostCPE = cpeVulnersString;
                            }
                        } else if (!cpeString.isEmpty()) {
                            if (cpeString.contains("cpe:/a:")) {
                                serviceCPE = cpeString;
                            } else {
                                hostCPE = cpeString;
                            }
                        }

                        Element hostCpeElement = new Element("host_cpe");
                        hostCpeElement.setText(hostCPE);
                        result.addContent(hostCpeElement);

                        Element serviceCpeElement = new Element("service_cpe");
                        serviceCpeElement.setText(serviceCPE);
                        result.addContent(serviceCpeElement);

                        Element host = new Element("host");
                        host.setText(hostString);
                        result.addContent(host);

                        Element port = new Element("port");
                        port.setText(portString + "/udp");
                        result.addContent(port);

                        if (!cveList.isEmpty()) {
                            for (String cveString : cveList) {
                                Element nvt = new Element("nvt");
                                result.addContent(nvt);
                                Element cve = new Element("cve");
                                cve.setText(cveString);
                                nvt.addContent(cve);
                            }
                        }
                    }
                } else {
                    if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
                        Logger.getAnonymousLogger().info("Ignored a host without any TCP or UDP ports: " + hostString);
                    }
                }
            }

            try {
                String vulnScanReportFilePath = ProjectProperties.getProperty("vulnerability-scan-path");
                XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
                //output.output(root, System.out);
                output.output(root_root, new FileOutputStream(vulnScanReportFilePath));
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Error during XML file output.");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "OpenVAS XML could not be generated.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vuln-scan-report, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The vulnerability report was successfully loaded.");
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vuln-scan-report, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("topology/hosts-interfaces")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_hostsinterfaces(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/hosts-interfaces, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("hosts-interfaces.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare to receive the CSV file contents.
            String hostsInterfacesFilePath = ProjectProperties.getProperty("host-interfaces-path");
            ArrayList<String> csvLines = new ArrayList<String>();

            // Check if there are considered networks.
            ServletContext context = request.getSession().getServletContext();
            if (context.getAttribute("netip") == null) {
                context.setAttribute("netip", new ProtectedNetworks());
            }
            ProtectedNetworks protectedNetworks = (ProtectedNetworks) context.getAttribute("netip");

            // Parse the JSON.
            try {
                JSONArray hostsInterfacesJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < hostsInterfacesJsonArray.length(); i++) {
                    JSONObject hostJsonObject = hostsInterfacesJsonArray.getJSONObject(i);
                    String hostname = hostJsonObject.getString("hostname");
                    String interface_name = hostJsonObject.getString("interface_name");
                    String ip_address = hostJsonObject.getString("ip_address");
                    String connected_to_wan = String.valueOf(hostJsonObject.getBoolean("connected_to_wan"));

                    String line = hostname + ";" + interface_name + ";" + ip_address + ";" + connected_to_wan + ";1";
                    if (protectedNetworks.belongsToNetwork(ip_address)) {
                        csvLines.add(line);
                    }
                }
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/hosts-interfaces, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Generate the CSV file.
            try {
                PrintWriter writer = new PrintWriter(hostsInterfacesFilePath);
                for (String l : csvLines) {
                    writer.println(l);
                }
                writer.close();
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Error while exporting to CSV");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, hosts-interfaces.csv could not be created.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/hosts-interfaces, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The hosts-interfaces list has been successfully loaded.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/hosts-interfaces, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/hosts-interfaces, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/topology/vlans")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_vlans(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/vlans, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("vlans.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare to receive the CSV file contents.
            String vlansFilePath = ProjectProperties.getProperty("vlans-path");
            ArrayList<String> csvLines = new ArrayList<String>();

            // Check if there are considered networks.
            ServletContext context = request.getSession().getServletContext();
            if (context.getAttribute("netip") == null) {
                context.setAttribute("netip", new ProtectedNetworks());
            }
            ProtectedNetworks protectedNetworks = (ProtectedNetworks) context.getAttribute("netip");

            // Parse the JSON.
            try {

                JSONArray vlansJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < vlansJsonArray.length(); i++) {
                    JSONObject vlansJsonObject = vlansJsonArray.getJSONObject(i);

                    String name = vlansJsonObject.getString("name");
                    String address = vlansJsonObject.getString("address");
                    String netmask = String.valueOf(vlansJsonObject.getInt("netmask"));
                    String gateway = vlansJsonObject.getString("gateway");

                    String line = name + ";" + address + ";" + netmask + ";" + gateway;

                    if (protectedNetworks.belongsToNetwork(gateway)) {
                        csvLines.add(line);
                    }
                }

            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vlans, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Generate the CSV file.
            try {
                PrintWriter writer = new PrintWriter(vlansFilePath);
                for (String l : csvLines) {
                    writer.println(l);
                }
                writer.close();
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Error while exporting to CSV");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, vlans.csv could not be created.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vlans, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The vlans list has been successfully loaded.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vlans, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/vlans, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/topology/flow-matrix")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_flowmatrix(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/flow-matrix, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("flow-matrix.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare to receive the CSV file contents.
            String flowMatrixFilePath = ProjectProperties.getProperty("flow-matrix-path");
            ArrayList<String> csvLines = new ArrayList<String>();

            // Check if there are considered networks.
            ServletContext context = request.getSession().getServletContext();
            if (context.getAttribute("netip") == null) {
                context.setAttribute("netip", new ProtectedNetworks());
            }
            ProtectedNetworks protectedNetworks = (ProtectedNetworks) context.getAttribute("netip");

            // Parse the JSON.
            try {
                JSONArray flowMatrixJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < flowMatrixJsonArray.length(); i++) {
                    JSONObject flowMatrixJsonObject = flowMatrixJsonArray.getJSONObject(i);

                    String source = flowMatrixJsonObject.getString("source");
                    if (!protectedNetworks.belongsToNetwork(source)) {
                        if (ProjectProperties.getProperty("replace-internet-with-gw").equalsIgnoreCase("true")) {
                            source = protectedNetworks.gatewayAddress();
                        } else {
                            source = "internet";
                        }
                    }

                    String destination = flowMatrixJsonObject.getString("destination");
                    if (!protectedNetworks.belongsToNetwork(destination)) {
                        if (ProjectProperties.getProperty("replace-internet-with-gw").equalsIgnoreCase("true")) {
                            destination = protectedNetworks.gatewayAddress();
                        } else {
                            destination = "internet";
                        }
                    }

                    if (source.equals("internet") && destination.equals("internet")) {
                        System.out.println("Both " + flowMatrixJsonObject.getString("source") + " & " + flowMatrixJsonObject.getString("destination") + " are considered outside of the considered network. Ignored.");
                        continue;
                    }

                    String source_port = flowMatrixJsonObject.getString("source_port");
                    String destination_port = flowMatrixJsonObject.getString("destination_port");
                    String protocol = flowMatrixJsonObject.getString("protocol");

                    String line = "\"" + source + "\";\"" + destination + "\";\"" + source_port + "\";\"" + destination_port + "\";\"" + protocol + "\"";
                    csvLines.add(line);
                }
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/flow-matrix, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Generate the CSV file.
            try {
                PrintWriter writer = new PrintWriter(flowMatrixFilePath);
                for (String l : csvLines) {
                    writer.println(l);
                }
                writer.close();
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Error while exporting to CSV");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, flow-matrix.csv could not be created.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/flow-matrix, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The flow matrix was successfully loaded.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/flow-matrix, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/flow-matrix, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("topology/routing")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_topology_routing(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/topology/routing, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            LoggingHelperFunctions.logToFile("routing.json", jsonString);

            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare to receive the CSV file contents.
            String routingFilePath = ProjectProperties.getProperty("routing-path");
            ArrayList<String> csvLines = new ArrayList<String>();

            // Check if there are considered networks.
            ServletContext context = request.getSession().getServletContext();
            if (context.getAttribute("netip") == null) {
                context.setAttribute("netip", new ProtectedNetworks());
            }
            ProtectedNetworks protectedNetworks = (ProtectedNetworks) context.getAttribute("netip");

            // Parse the JSON.
            try {
                JSONArray routingJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < routingJsonArray.length(); i++) {
                    JSONObject routingJsonObject = routingJsonArray.getJSONObject(i);

                    String host = routingJsonObject.getString("hostname");
                    String destination = routingJsonObject.getString("destination");
                    String mask = routingJsonObject.getString("mask");
                    String gateway = routingJsonObject.getString("gateway");
                    String interface_name = routingJsonObject.getString("interface");

                    String line = host + ";" + destination + ";" + mask + ";" + gateway + ";" + interface_name;

                    if (protectedNetworks.belongsToNetwork(gateway)) {
                        csvLines.add(line);
                    }
                }
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/routing, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Generate the CSV file.
            try {
                PrintWriter writer = new PrintWriter(routingFilePath);
                for (String l : csvLines) {
                    writer.println(l);
                }
                writer.close();
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Error while exporting to CSV");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, routing.csv could not be created.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/routing, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The routing table was successfully loaded.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/routing, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/topology/routing, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private void initialization_procedure(HttpServletRequest request, String databasePath, String topologyFilePath, String costParametersFolderPath) throws Exception {

        Logger.getAnonymousLogger().info("Loading the vulnerability and remediation database");
        Database database = new Database(databasePath);

        Logger.getAnonymousLogger().info("Loading the XML topology. (" + topologyFilePath + ")");
        InformationSystem informationSystem = InformationSystemManagement.loadTopologyXMLFile(topologyFilePath, database);

        Logger.getAnonymousLogger().info("Preparing MulVAL inputs");
        File mulvalInputFile = new File(ProjectProperties.getProperty("mulval-input"));
        informationSystem.exportToMulvalDatalogFile(mulvalInputFile.getAbsolutePath());

        long startTime = System.currentTimeMillis();

        Logger.getAnonymousLogger().info("Executing MulVAL");
        // Set the filename of the MulVAL attack graph XML output.
        String outputFolderPath = ProjectProperties.getProperty("output-path");
        String attackGraphXMLOutput = "/attkgrph";
        File mulvalOutputFile = new File(outputFolderPath + attackGraphXMLOutput + ".xml");
        if (mulvalOutputFile.exists()) {
            mulvalOutputFile.delete();
        }
        AttackGraph attackGraph = InformationSystemManagement.executeMulval(mulvalInputFile, mulvalOutputFile, attackGraphXMLOutput);

        attackGraph.loadMetricsFromTopology(informationSystem);

        if (attackGraph == null) {
            throw new MulvalEmptyAttackGraphException("The attack graph is empty.");
        }

        long stopTime = System.currentTimeMillis();

        Logger.getAnonymousLogger().info("[TIMING] MulVal attack graph generation : " + (stopTime - startTime) + " ms");

        Logger.getAnonymousLogger().info("Compute parents and children");
        attackGraph.computeAllParentsAndChildren();


        attackGraph.loadMetricsFromTopology(informationSystem);


        Logger.getAnonymousLogger().info("Associating all vertices to their respective network hosts.");
        try {
            attackGraph.vertexToHostAssociations = VertexHostAssociation.AssociateHostsToVertices(informationSystem, attackGraph);
            attackGraph.enrichVertexInfo(informationSystem);
        } catch (Exception e) {
            e.printStackTrace();
        }

        startTime = System.currentTimeMillis();
        
        Logger.getAnonymousLogger().info("Building the reduced graph");
        AttackGraph reducedGraph = attackGraph;
        reducedGraph.vertexToHostAssociations = VertexHostAssociation.AssociateHostsToVertices(informationSystem, reducedGraph);
        LoggingHelperFunctions.saveGraphToFile("MulVAL.json", attackGraph, "MulVAL graph.");
        LoggingHelperFunctions.saveGraphToFile("Reduced-1.json", reducedGraph, "MulVAL reduced graph.");

        stopTime = System.currentTimeMillis();

        Logger.getAnonymousLogger().info("[TIMING] Reduced attack graph : " + (stopTime - startTime) + " ms");

        
        int parentsParam = Integer.parseInt(ProjectProperties.getProperty("parents-param"));

        int naiveRisk = Integer.parseInt(ProjectProperties.getProperty("naive-risk"));

        double nr_Value = Double.parseDouble(ProjectProperties.getProperty("naive-risk-value"));

        boolean checkOG = true;

        ServletContext context = request.getSession().getServletContext();

        if (context.getAttribute("sa_tradeoff") == null) {
            context.setAttribute("sa_tradeoff", 0.6);
        }

        if (context.getAttribute("sp_tradeoff") == null) {
            context.setAttribute("sp_tradeoff", 2);
        }

        int sp_tdoff = (int) request.getSession(true).getServletContext().getAttribute("sp_tradeoff");

        if (sp_tdoff >= 5) {
            checkOG = false;
        }
        
//        VertexHostAssociation.RefreshAssociationTables(reducedGraph);

        stopTime = System.currentTimeMillis();
        AttackGraph reducedGraphWithCycles = null;
        
        reducedGraphWithCycles = (AttackGraph) reducedGraph.clone();

        LoggingHelperFunctions.saveGraphToFile("Final.json", reducedGraph, "Reduced graph.");


        Logger.getAnonymousLogger().info("Generating the attack graph JSON to be sent to the iRE Server.");
        JSONObject attackGraphJson = null;
        try {
            if (ProjectProperties.getProperty("ire-graph-with-cycles").equalsIgnoreCase("true") && (reducedGraphWithCycles != null)) {
                attackGraphJson = mulval_attack_graph(reducedGraphWithCycles.toDomElement(), reducedGraphWithCycles);
                LoggingHelperFunctions.saveGraphToFile("iRE.json", reducedGraphWithCycles, "Reduced graph.");
            } else {
                attackGraphJson = mulval_attack_graph(reducedGraph.toDomElement(), reducedGraph);
                LoggingHelperFunctions.saveGraphToFile("iRE.json", reducedGraph, "Reduced graph.");
            }
        } catch (JSONException e) {
            e.printStackTrace();
            throw e;
        }

        // Create a new thread to send the attack graph to the iRE.
        // To avoid the client hanging in case the iRE Server isn't responding.
        Logger.getAnonymousLogger().info("Sending the attack graph JSON to the iRE Server.");
        final String ireUrl = ProjectProperties.getProperty("ire-url-topology");
        final JSONObject finalAttackGraphJson = attackGraphJson;
        Thread ireConnectThread = new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Logger.getAnonymousLogger().info("Thread created to send the attack graph to iRE.");

                        try {
                            if (finalAttackGraphJson != null) {
                                URL ireConnectionUrl = new URL(ireUrl);
                                HttpURLConnection ireConnection = (HttpURLConnection) ireConnectionUrl.openConnection();
                                ireConnection.setDoOutput(true);
                                ireConnection.setRequestMethod("POST");
                                ireConnection.setRequestProperty("Content-Type", "application/json");
                                // Set a connection timeout of 5 seconds.
                                ireConnection.setConnectTimeout(5 * 1000);

                                // Prepare the final payload to be sent to the iRE Server.
                                JSONObject payload = new JSONObject();
                                payload.put("attack_graph", finalAttackGraphJson);

                                // Add the attack graph.
                                JSONObject result = RestApplication.prepareResponseJSONStructure(
                                        RestApplication.InternalTopicName.TEST, payload,
                                        RestApplication.ResultJSONStructureStatus.OK,
                                        "The MulVAL attack graph was successfully retrieved."
                                );

                                DataOutputStream wr = new DataOutputStream(ireConnection.getOutputStream());
                                wr.write(result.toString().getBytes());
                                Integer responseCode = ireConnection.getResponseCode();

                                Logger.getAnonymousLogger().info("Attack graph posted to the iRE. Response code: " + responseCode);
                            } else {
                                Logger.getAnonymousLogger().warning("Cannot connect to the iRE. Attack graph not posted");
                            }
                        } catch (Exception e) {
                            Logger.getAnonymousLogger().warning("Cannot connect to the iRE. Attack graph not posted");
                            e.printStackTrace();
                        }

                        Logger.getAnonymousLogger().info("Thread finished");
                    }
                }
        );
        ireConnectThread.start();

        // TODO: ENABLE ATTACK PATHS
        //RestApplication.print_message(Level.INFO, "" + attackPaths.size() + " attack paths scored.");
        Monitoring monitoring = new Monitoring(costParametersFolderPath);
        //monitoring.setAttackPathList(attackPaths);
        monitoring.setInformationSystem(informationSystem);
        monitoring.setAttackGraph((MulvalAttackGraph) attackGraph);

        request.getSession(true).getServletContext().setAttribute("database", database);
        request.getSession(true).getServletContext().setAttribute("monitoring", monitoring);

        // Store state information for the /system/info call.
        SystemInformation info = new SystemInformation();
        info.setInitializedDateNow();
        info.setInitializedState(true);
        request.getSession(true).getServletContext().setAttribute("info", info);


        // Start the bus listeners.
        Thread bus_topic_config = new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        String topic = RestApplication.TopicName.SOHO_CONFIG.getTopic();
                        Logger.getAnonymousLogger().info(topic + " Thread created to subscribe to the bus");

                        try {
                            TopologyConfigMessageConsumer consumer = new TopologyConfigMessageConsumer(topic, "POST", "/topology/config");
                            TopicSubscriptionManager.subscribeTo(ProjectProperties.getProperty("bus-uri"), topic, consumer);
                        } catch (Exception e) {
                            Logger.getAnonymousLogger().warning("[GET:/initialize] Error when contacting the information bus: " + topic);
                            e.printStackTrace();
                        }

                        Logger.getAnonymousLogger().info(topic + " Thread finished");
                    }
                }
        );
        bus_topic_config.start();

        // Performing calls #4 (GET:/topology) & #16 (GET:/attack-graph/risk) on localhost,
        // as they also post the result to the Bus.
        // The code generating the JSON response for each call is tightly coupled with the Rest call functionality.
        // This is easier for now.
        Integer HTTPresponse = 0;

        try {
            Logger.getAnonymousLogger().info("Posting the XML topology to: " + TopicName.NETWORK_TOPOLOGY.getTopic());
            HTTPresponse = perform_http_get("http://127.0.0.1:8080/ag-engine-server/rest/json/v2/topology");
            Logger.getAnonymousLogger().info("Response code: " + HTTPresponse);

            Logger.getAnonymousLogger().info("Posting the risk rating of all network hosts to: " + TopicName.NETWORK_RISK.getTopic());
            HTTPresponse = perform_http_get("http://127.0.0.1:8080/ag-engine-server/rest/json/v2/attack-graph/risk");
            Logger.getAnonymousLogger().info("Response code: " + HTTPresponse);
        } catch (Exception e) {
            Logger.getAnonymousLogger().warning("[GET:/initialize] Error when contacting the information bus: " + TopicName.NETWORK_TOPOLOGY.getTopic() + " or " + TopicName.NETWORK_RISK.getTopic());
            e.printStackTrace();
        }
    }

    private Integer perform_http_get(String uri) throws Exception {
        Integer HTTPresponse = 0;

        // Open the connection.
        URL url = new URL(uri);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setDoInput(true);
        conn.setRequestProperty("Accept", "application/json");

        // Get the response.
        HTTPresponse = conn.getResponseCode();
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));

        String response = "";
        String tmp = "";
        while ((tmp = rd.readLine()) != null) {
            response += tmp;
        }

        // Print the response.
        // System.out.println("RESPONSE: " + response);

        conn.disconnect();
        return HTTPresponse;
    }

    @GET
    @Path("/initialize")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_initialize(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare the necessary file paths.
            String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
            String databasePath = ProjectProperties.getProperty("database-path");
            String topologyFilePath = ProjectProperties.getProperty("topology-path");

            // Generate the topology from the existing files on disk.
            try {
                // Generate the XML topology using the Data Extraction subsystem.
                Logger.getAnonymousLogger().info("Generating the XML topology from on-disk data. (" + topologyFilePath + ")");
                InformationSystemManagement.generateXmlTopologyFromDiskFiles();
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Cannot generate the topology XML");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, couldn't generate the topology XML.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            try {
                initialization_procedure(request, databasePath, topologyFilePath, costParametersFolderPath);
            } catch (MulvalEmptyAttackGraphException e) {
                Logger.getAnonymousLogger().severe("The attack graph is empty");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the attack graph is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            } catch (JSONException e) {
                Logger.getAnonymousLogger().severe("JSON output for the iRE could not be generated");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON output for the iRE could not be generated.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("Unknown exception");
                e.printStackTrace();
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The initialization procedure was successful.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private void store_xml_topology(String topologyXML, String topologyFilePath) throws Exception {
        if (topologyXML == null || topologyXML.isEmpty()) {
            Logger.getAnonymousLogger().severe("Input text string is empty");
            throw new IllegalArgumentException("[ERROR] The input text string is empty.");
        }

        PrintWriter out = new PrintWriter(topologyFilePath);
        out.print(topologyXML);
        out.close();
    }

    @POST
    @Path("/initialize")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_initialize(@Context HttpServletRequest request, String xmlString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [XML] Received: " + xmlString);
        }

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Prepare the necessary file paths.
            String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
            String databasePath = ProjectProperties.getProperty("database-path");
            String topologyFilePath = ProjectProperties.getProperty("topology-path");

            // Store the given XML topology to disk.
            try {
                RestApplication.print_message(Level.INFO, "Storing XML topology in " + topologyFilePath);
                store_xml_topology(xmlString, topologyFilePath);
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Cannot generate the topology XML");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, failed to store the topology XML.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            try {
                initialization_procedure(request, databasePath, topologyFilePath, costParametersFolderPath);
            } catch (MulvalEmptyAttackGraphException e) {
                Logger.getAnonymousLogger().severe("The attack graph is empty");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the attack graph is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            } catch (JSONException e) {
                Logger.getAnonymousLogger().severe("JSON output for the iRE could not be generated");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON output for the iRE could not be generated.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("Unknown exception");
                e.printStackTrace();
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The initialization procedure was successful.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/initialize")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response POST_initialize(@Context HttpServletRequest request,
                                    @FormDataParam("file") InputStream uploadedInputStream,
                                    @FormDataParam("file") FormDataContentDisposition fileDetail,
                                    @FormDataParam("file") FormDataBodyPart body) throws Exception {
        Logger.getAnonymousLogger().info("[API CALL] [START] [MULTIPLE INPUTS] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            if (!body.getMediaType().equals(MediaType.APPLICATION_XML_TYPE) && !body.getMediaType().equals(MediaType.TEXT_XML_TYPE) && !body.getMediaType().equals(MediaType.TEXT_PLAIN_TYPE)) {
                Logger.getAnonymousLogger().severe("Input file is not an XML file");

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The file is not an XML file.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] [MULTIPLE INPUTS] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            String xmlFileString = IOUtils.toString(uploadedInputStream, "UTF-8");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] [MULTIPLE INPUTS] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return POST_initialize(request, xmlFileString);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] [MULTIPLE INPUTS] " + request.getMethod() + ":/v2/initialize, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    public static JSONObject mulval_attack_graph(Element attackGraphXML, AttackGraph attackGraph) {
        JSONObject result = new JSONObject();

        // Get the standard structures, as generated by the original CyberCAPTOR.
        JSONObject tmp = XML.toJSONObject(new XMLOutputter(Format.getCompactFormat()).outputString(attackGraphXML));
        JSONArray arcs = tmp.getJSONObject("attack_graph").getJSONObject("arcs").getJSONArray("arc");
        JSONArray vertices = tmp.getJSONObject("attack_graph").getJSONObject("vertices").getJSONArray("vertex");

        // Rebuild the host-to-vertex association table.
        //
        // The one produced from the XML conversion is hideous,
        // and quite frankly the people who developed the XML conversion object
        // should be condemned to support systems written in LISP or even HASKELL for the rest of their lives...
        //
        // I feel bad for using THAT table in the V1 API...
        JSONArray associations = new JSONArray();
        if ((attackGraph.vertexToHostAssociations != null) && (attackGraph.vertexToHostAssociations.isEmpty() == false)) {
            for (VertexHostAssociation.VertexList l : attackGraph.vertexToHostAssociations) {
                if (l.vertices.isEmpty() == false) {
                    // Add the general info.
                    JSONObject list = new JSONObject();
                    list.put("type", l.type.name());

                    // Add the list contents.
                    // IP|PORT|PROTOCOL|SERVICE    IP|PORT|PROTOCOL    IP|PORT         IP
                    // FULL_INFO                   PARTIAL_INFO        LIMITED_INFO    IP_ONLY
                    if (l.type == VertexHostAssociation.VertexListType.FULL_INFO) {
                        list.put("ip", l.ip);
                        list.put("port", l.port);
                        list.put("protocol", l.protocol);
                        list.put("service", l.service.getName());
                        list.put("hostname", l.hostname);

                        // Optional UUID field, only for Cyber-Trust registered devices.
                        if (!l.uuid.isEmpty()) {
                            list.put("id", l.uuid);
                        }

                        // Report both types of vertices.
                        JSONObject listVertices = new JSONObject();
                        list.put("relevant_vertices", listVertices);

                        JSONArray alertsTable = new JSONArray();
                        JSONArray securityConditionsTable = new JSONArray();
                        boolean foundAL = false, foundSC = false;

                        for (Vertex v : l.vertices) {
                            if (v.type == Vertex.VertexType.AND) {
                                alertsTable.put(v.id);
                                foundAL = true;
                            } else {
                                securityConditionsTable.put(v.id);
                                foundSC = true;
                            }
                        }

                        if (foundAL)
                            listVertices.put("AL", alertsTable);
                        if (foundSC)
                            listVertices.put("SC", securityConditionsTable);
                    } else if (l.type == VertexHostAssociation.VertexListType.PARTIAL_INFO) {
                        list.put("ip", l.ip);
                        list.put("port", l.port);
                        list.put("protocol", l.protocol);
                        list.put("hostname", l.hostname);

                        // Optional UUID field, only for Cyber-Trust registered devices.
                        if (!l.uuid.isEmpty()) {
                            list.put("id", l.uuid);
                        }

                        // Report both types of vertices.
                        JSONObject listVertices = new JSONObject();
                        list.put("relevant_vertices", listVertices);

                        JSONArray alertsTable = new JSONArray();
                        JSONArray securityConditionsTable = new JSONArray();
                        boolean foundAL = false, foundSC = false;

                        for (Vertex v : l.vertices) {
                            if (v.type == Vertex.VertexType.AND) {
                                alertsTable.put(v.id);
                                foundAL = true;
                            } else {
                                securityConditionsTable.put(v.id);
                                foundSC = true;
                            }
                        }

                        if (foundAL)
                            listVertices.put("AL", alertsTable);
                        if (foundSC)
                            listVertices.put("SC", securityConditionsTable);
                    } else if (l.type == VertexHostAssociation.VertexListType.LIMITED_INFO) {
                        list.put("ip", l.ip);
                        list.put("port", l.port);
                        list.put("hostname", l.hostname);

                        // Optional UUID field, only for Cyber-Trust registered devices.
                        if (!l.uuid.isEmpty()) {
                            list.put("id", l.uuid);
                        }

                        // Report both types of vertices.
                        JSONObject listVertices = new JSONObject();
                        list.put("relevant_vertices", listVertices);

                        JSONArray alertsTable = new JSONArray();
                        JSONArray securityConditionsTable = new JSONArray();
                        boolean foundAL = false, foundSC = false;

                        for (Vertex v : l.vertices) {
                            if (v.type == Vertex.VertexType.AND) {
                                alertsTable.put(v.id);
                                foundAL = true;
                            } else {
                                securityConditionsTable.put(v.id);
                                foundSC = true;
                            }
                        }

                        if (foundAL)
                            listVertices.put("AL", alertsTable);
                        if (foundSC)
                            listVertices.put("SC", securityConditionsTable);
                    } else {
                        list.put("ip", l.ip);
                        list.put("hostname", l.hostname);

                        // Optional UUID field, only for Cyber-Trust registered devices.
                        if (!l.uuid.isEmpty()) {
                            list.put("id", l.uuid);
                        }

                        // Report both types of vertices.
                        JSONObject listVertices = new JSONObject();
                        list.put("relevant_vertices", listVertices);

                        JSONArray alertsTable = new JSONArray();
                        JSONArray securityConditionsTable = new JSONArray();
                        boolean foundAL = false, foundSC = false;

                        for (Vertex v : l.vertices) {
                            if (v.type == Vertex.VertexType.AND) {
                                alertsTable.put(v.id);
                                foundAL = true;
                            } else {
                                securityConditionsTable.put(v.id);
                                foundSC = true;
                            }
                        }

                        if (foundAL)
                            listVertices.put("AL", alertsTable);
                        if (foundSC)
                            listVertices.put("SC", securityConditionsTable);
                    }

                    associations.put(list);
                }
            }
        }

        // Prepare the final JSON object.
        // Remember to also send it during the /initialize calls to the iIRE.
        result.put("arcs", arcs);
        result.put("vertices", vertices);
        result.put("associations", associations);
        return result;
    }

    @GET
    @Path("/attack-graph")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackgraph(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            payload.put("attack_graph", mulval_attack_graph(monitoring.getAttackGraph().toDomElement(), monitoring.getAttackGraph()));
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The MulVAL attack graph was successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-graph/risk")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackgraph_risk(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph/risk, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_RISK, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/risk, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            JSONArray hosts = new JSONArray();
            payload.put("hosts", hosts);

            AttackGraph graph = monitoring.getAttackGraph();

            ArrayList<Host> hostList = monitoring.getInformationSystem().getTopology().getHosts();
            for (Host h : hostList) {
                JSONObject host = new JSONObject();
                hosts.put(host);

                host.put("name", h.getName());
                host.put("ip", h.getFirstIPAddress());

                if (!h.getId().isEmpty()) {
                    host.put("id", h.getId());
                }

                double risk = 0.0;

                int counterRoot = 0;
                int counterUser = 0;
                int counterZero = 0;

                double sumRoot = 0;
                double sumUser = 0;
                double sumZero = 0;

                // System.out.println("/////////////////////////////////////////////////");
                // System.out.println(h.getName());
                // System.out.println("..............................");

                for (int i = 1; i <= graph.vertices.size(); i++) {

                    if (graph.vertices.get(i).type == Vertex.VertexType.OR) {
                        if (graph.vertices.get(i).concernedMachine != null) {
                            //System.out.println(graph.vertices.get(i).concernedMachine.getName());

                            if (graph.vertices.get(i).concernedMachine.getName() == h.getName()) {
                                if (graph.vertices.get(i).fact.factString.contains("root") && graph.vertices.get(i).fact.factString.contains("execCode")) {
                                    counterRoot++;
                                    //System.out.println(graph.vertices.get(i).unconditionalProb);
                                    sumRoot += graph.vertices.get(i).unconditionalProb;
                                }

                                if (graph.vertices.get(i).fact.factString.contains("user") && graph.vertices.get(i).fact.factString.contains("execCode")) {
                                    counterUser++;
                                    //System.out.println(graph.vertices.get(i).unconditionalProb);
                                    sumUser += graph.vertices.get(i).unconditionalProb;
                                }
                            }
                        }
                    } else {

                        counterZero++;
                        sumZero += graph.vertices.get(i).unconditionalProb;

                    }
                }

                if (counterRoot != 0) {
                    //System.out.println("ROOT OCCASION");
                    risk = sumRoot * 1.00000 / counterRoot;
                } else if (counterUser != 0) {
                    //System.out.println("USER OCCASION");
                    risk = sumUser * 1.00000 / counterUser;
                } else {
                    //System.out.println("OTHER OCCASION");
                    risk = sumZero * 1.00000 / counterZero;
                }
                //System.out.println(risk);

                host.put("risk", risk);
            }

            final String URI = ProjectProperties.getProperty("bus-uri");
            final String topic = TopicName.NETWORK_RISK.getTopic();

            response = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_RISK, payload, ResultJSONStructureStatus.OK, "Smart home risks were successfully calculated.");

            try {
                TopicMessageSender.sendTo(URI, topic, response.toString());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("[GET:/attack-graph/risk] Error when contacting the information bus: " + topic);
                e.printStackTrace();
            }

            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/risk, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(TopicName.NETWORK_RISK, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/risk, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-graph/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackgraph_topological(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            JSONObject tmp = AttackPathManagement.getAttackGraphTopologicalJson(monitoring);
            JSONArray arcs = tmp.getJSONObject("arcs").getJSONArray("arc");
            JSONArray vertices = tmp.getJSONObject("vertices").getJSONArray("vertex");

            JSONObject attackGraphJSON = new JSONObject();
            attackGraphJSON.put("arcs", arcs);
            attackGraphJSON.put("vertices", vertices);

            payload.put("topological_attack_graph", attackGraphJSON);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The topological attack graph was successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-graph/remediations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackgraph_remediations(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Run the block-nodes algorithm for every AND node of the graph.
            JSONArray actions = new JSONArray();
            try {
                ArrayList<BlockNode.Solution> totalSolutions = new ArrayList<BlockNode.Solution>();

                AttackGraph tmpAttackGraph = null;
                if (ProjectProperties.getProperty("ire-graph-with-cycles").equalsIgnoreCase("true") && (monitoring.getAttackGraph() != null)) {
                    tmpAttackGraph = (AttackGraph) monitoring.getAttackGraph().clone();
                } else {
                    tmpAttackGraph = (AttackGraph) monitoring.getAttackGraph().clone();
                }

                // First round, solve for all AND nodes and find all directly affected nodes for each solution.

                // Second round, identify all indirectly affected nodes for each solution.
                // Identical solutions targeting different nodes will affect the same nodes.
                // e.g. a FW rule may solve nodes x and y (each affecting a different set of nodes),
                //      when applied it solves x but also y and its affected nodes,
                //      so the affected nodes list should also include the nodes of y.

                // Third round, collapse all identical solutions targeting different nodes.
                Set<BlockNode.Solution> solutionsFinalList = new HashSet<BlockNode.Solution>(totalSolutions);


                // Keeps track of each unique set of firewall rules that blocks a specific node.
                // To identify the choice made by the user.
                int solutionID = 1;

                boolean checkFWO = true;
                double sa_tdoff = (double) request.getSession(true).getServletContext().getAttribute("sa_tradeoff");
                System.out.println("[SA_PARAM] ---> " + sa_tdoff);

                if (sa_tdoff >= 0.5) {
                    checkFWO = false;
                }


                if (ProjectProperties.getProperty("global-fw-rules-only").equalsIgnoreCase("false") || checkFWO == false) {
                    // Third round, generate the JSON response.
                    for (BlockNode.Solution s : solutionsFinalList) {
                        JSONObject action = new JSONObject();
                        actions.put(action);

                        JSONArray affectedNodes = new JSONArray();
                        action.put("affected_nodes", affectedNodes);
                        for (Vertex av : s.affectedNodes) {
                            affectedNodes.put(av.id);
                        }

                        action.put("id", solutionID);
                        action.put("global", false);

                        JSONObject solution = new JSONObject();
                        action.put("solution", solution);
                        JSONArray rulePairs = new JSONArray();
                        for (BlockNode.NetworkPair fw : s.rules) {
                            JSONArray rulePair = new JSONArray();
                            for (String rule : fw.generateFirewallRule()) {
                                rulePair.put(rule);
                            }
                            rulePairs.put(rulePair);
                        }
                        solution.put("rules", rulePairs);

                        JSONArray pfsenseRules = new JSONArray();
                        for (BlockNode.NetworkPair fw : s.rules) {
                            pfsenseRules.put(fw.generatePfSenseRule());
                        }
                        solution.put("pfsense", pfsenseRules);

                        solutionID++;
                    }
                }

                // Check if there are considered networks.
                ServletContext context = request.getSession().getServletContext();
                if (context.getAttribute("netip") == null) {
                    context.setAttribute("netip", new ProtectedNetworks());
                }
                ProtectedNetworks protectedNetworks = (ProtectedNetworks) context.getAttribute("netip");

                // Fourth round, add global rules for each and every host.
                ArrayList<Host> hostList = monitoring.getInformationSystem().getTopology().getHosts();
                for (Host h : hostList) {

                    // Ignore the gateway.
                    if (h.getFirstIPAddress().toString().equals(protectedNetworks.gatewayAddress())) {
                        continue;
                    }

                    JSONObject action = new JSONObject();
                    actions.put(action);

                    // Collect all relevant vertices from all nodes associated with this host.
                    JSONArray affectedNodes = new JSONArray();
                    action.put("affected_nodes", affectedNodes);
                    Set<Vertex> allAffectedNodes = new HashSet<Vertex>();
                    for (VertexHostAssociation.VertexList l : tmpAttackGraph.vertexToHostAssociations) {
                        if (l.hostname.equalsIgnoreCase(h.getName())) {
                            allAffectedNodes.addAll(l.vertices);
                        }
                    }
                    for (Vertex av : allAffectedNodes) {
                        affectedNodes.put(av.id);
                    }

                    action.put("id", solutionID);
                    action.put("global", true);

                    // Make a rule for every IP of the host.
                    //   iptables -A INPUT -s [IP] -j DROP
                    //   iptables -A OUTPUT -s [IP] -j DROP
                    JSONObject solution = new JSONObject();
                    action.put("solution", solution);
                    JSONArray rulePairs = new JSONArray();
                    for (Interface i : h.getInterfaces().values()) {
                        JSONArray rulePair = new JSONArray();
                        rulePair.put("iptables -A INPUT -s " + i.getAddress().getAddress() + " -j DROP");
                        rulePair.put("iptables -A OUTPUT -s " + i.getAddress().getAddress() + " -j DROP");
                        rulePairs.put(rulePair);
                    }
                    solution.put("rules", rulePairs);

                    //   easyrule block [INTERFACE] [IP]
                    JSONArray pfsenseRules = new JSONArray();
                    for (Interface i : h.getInterfaces().values()) {
                        pfsenseRules.put("easyrule block " + ProjectProperties.getProperty("pfsense-interface") + " " + i.getAddress().getAddress());
                    }
                    solution.put("pfsense", pfsenseRules);

                    solutionID++;
                }
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Unknown exception");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            payload.put("actions", actions);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The actions to block the specified nodes were successfully generated.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("/attack-graph/remediations/block-nodes")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response POST_attackgraph_remediations_blocknodes(@Context HttpServletRequest request, String jsonString) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + jsonString);
        }

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Parse the JSON to get the nodes to be blocked.
            ArrayList<Integer> nodesToBlock = new ArrayList<Integer>();
            try {
                JSONArray nodesJsonArray = new JSONArray(jsonString);

                for (int i = 0; i < nodesJsonArray.length(); i++) {
                    JSONObject o = nodesJsonArray.getJSONObject(i);
                    nodesToBlock.add(Integer.valueOf(o.getInt("node")));
                }
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                Logger.getAnonymousLogger().severe("Error during input JSON parsing");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "JSON input could not be parsed.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            JSONArray actions = new JSONArray();

            // Explore the remediations.
            try {
                ArrayList<BlockNode.Solution> totalSolutions = new ArrayList<BlockNode.Solution>();

                AttackGraph tmpAttackGraph = null;
                if (ProjectProperties.getProperty("ire-graph-with-cycles").equalsIgnoreCase("true") && (monitoring.getAttackGraph() != null)) {
                    tmpAttackGraph = (AttackGraph) monitoring.getAttackGraph().clone();
                } else {
                    tmpAttackGraph = (AttackGraph) monitoring.getAttackGraph().clone();
                }

                // First round, solve for all AND nodes and find all directly affected nodes for each solution.

                // Second round, identify all indirectly affected nodes for each solution.
                // Identical solutions targeting different nodes will affect the same nodes.
                // e.g. a FW rule may solve nodes x and y (each affecting a different set of nodes),
                //      when applied it solves x but also y and its affected nodes,
                //      so the affected nodes list should also include the nodes of y.


                // Third round, collapse all identical solutions targeting different nodes.
                Set<BlockNode.Solution> finalSolutions = new HashSet<BlockNode.Solution>(totalSolutions);

                // Keeps track of each unique set of firewall rules that blocks a specific node.
                // To identify the choice made by the user.
                int solutionID = 1;

                // Third round, generate the JSON response.
                for (BlockNode.Solution s : finalSolutions) {
                    JSONObject action = new JSONObject();
                    actions.put(action);

                    JSONArray affectedNodes = new JSONArray();
                    action.put("affected_nodes", affectedNodes);
                    for (Vertex av : s.affectedNodes) {
                        affectedNodes.put(av.id);
                    }

                    action.put("id", solutionID);
                    action.put("node", s.target.id);

                    JSONObject solution = new JSONObject();
                    action.put("solution", solution);
                    JSONArray rulePairs = new JSONArray();
                    for (BlockNode.NetworkPair fw : s.rules) {
                        JSONArray rulePair = new JSONArray();
                        for (String rule : fw.generateFirewallRule()) {
                            rulePair.put(rule);
                        }
                        rulePairs.put(rulePair);
                    }
                    solution.put("rules", rulePairs);

                    JSONArray pfsenseRules = new JSONArray();
                    for (BlockNode.NetworkPair fw : s.rules) {
                        pfsenseRules.put(fw.generatePfSenseRule());
                    }
                    solution.put("pfsense", pfsenseRules);

                    solutionID++;
                }
            } catch (NoSuchElementException e) {
                Logger.getAnonymousLogger().severe("Node ID is invalid: " + e.getMessage());
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The following node ID is invalid: " + e.getMessage() + ".");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            } catch (Exception e) {
                Logger.getAnonymousLogger().severe("Unknown exception");
                e.printStackTrace();

                payload = new JSONObject();
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            payload.put("actions", actions);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The actions to block the specified nodes were successfully generated.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/remediations/block-nodes, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/list")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_list(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/list, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/list, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            JSONArray attackPaths = new JSONArray();
            for (AttackPath p : monitoring.getAttackPathList()) {
                JSONObject path = new JSONObject();

                path.put("score", p.scoring);
                JSONArray arcs = new JSONArray();
                for (Arc a : p.arcs) {
                    JSONObject arc = new JSONObject();
                    arc.put("src", a.source.id);
                    arc.put("dst", a.destination.id);
                    arcs.put(arc);
                }
                path.put("arcs", arcs);

                attackPaths.put(path);
            }

            payload.put("attack_paths", attackPaths);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The attack paths were successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/list, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/list, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/number")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_number(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/number, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

                response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/number, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            payload.put("number", monitoring.getAttackPathList().size());
            response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.OK, "The number of attack paths was successfully retrieved.");

            final String URI = ProjectProperties.getProperty("bus-uri");
            final String topic = TopicName.APPLICABLE_MITIGATIONS.getTopic();

            try {
                TopicMessageSender.sendTo(URI, topic, response.toString());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("[GET:/attack-path/number] Error when contacting the information bus: " + topic);
                e.printStackTrace();
            }

            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/number, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/number, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_ID(@Context HttpServletRequest request, @PathParam("id") int id) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/" + id + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Check if the requested attack path actually exists.
            int attackPathsSize = monitoring.getAttackPathList().size();
            if ((id < 0) || (id >= attackPathsSize)) {
                String msg = "The attack path ID=" + id + " is invalid. There are only " + attackPathsSize + " attack paths generated ID=(0 to " + (attackPathsSize - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the requested attack path.
            Element tmpXML = AttackPathManagement.getAttackPathXML(monitoring, id);
            JSONObject tmp = XML.toJSONObject(new XMLOutputter(Format.getCompactFormat()).outputString(tmpXML));
            JSONArray arcs = tmp.getJSONObject("attack_path").getJSONObject("arcs").getJSONArray("arc");
            double score = tmp.getJSONObject("attack_path").getDouble("scoring");

            // Prepare the final JSON structure (the one generated by the XML-JSON converter is hideous).
            JSONObject path = new JSONObject();
            path.put("score", score);
            path.put("arcs", arcs);

            payload.put("attack_path", path);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The requested attack path was successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/{id}/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_ID_topological(@Context HttpServletRequest request, @PathParam("id") int id) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/" + id + "/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Check if the requested attack path actually exists.
            int attackPathsSize = monitoring.getAttackPathList().size();
            if ((id < 0) || (id >= attackPathsSize)) {
                String msg = "The attack path ID=" + id + " is invalid. There are only " + attackPathsSize + " attack paths generated ID=(0 to " + (attackPathsSize - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the requested attack path.
            JSONObject tmp = AttackPathManagement.getAttackPathTopologicalJson(monitoring, id);
            JSONArray arcs = tmp.getJSONObject("arcs").getJSONArray("arc");
            JSONArray vertices = tmp.getJSONObject("vertices").getJSONArray("vertex");

            // Prepare the final JSON structure (the one generated by the XML-JSON converter is hideous).
            JSONObject path = new JSONObject();
            path.put("arcs", arcs);
            path.put("vertices", vertices);

            payload.put("topological_attack_path", path);
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The requested attack path was successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/topological, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/{id}/remediations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_ID_remediations(@Context HttpServletRequest request, @PathParam("id") int id) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Check if the remediations database is empty.
            Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));
            if (db == null) {
                Logger.getAnonymousLogger().severe("The system database object is null");

                response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.ERROR, "Internal error, the system database object is null.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            // Check if the requested attack path actually exists.
            int attackPathsSize = monitoring.getAttackPathList().size();
            if ((id < 0) || (id >= attackPathsSize)) {
                String msg = "The attack path ID=" + id + " is invalid. There are only " + attackPathsSize + " attack paths generated ID=(0 to " + (attackPathsSize - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the remediations.
            Element tmpXML = AttackPathManagement.getRemediationXML(monitoring, id, db);
            JSONObject tmp = XML.toJSONObject(new XMLOutputter(Format.getCompactFormat()).outputString(tmpXML));
            JSONArray actions = tmp.getJSONObject("remediations").getJSONArray("remediation");

            payload.put("remediations", actions);
            response = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, payload, ResultJSONStructureStatus.OK, "The remediations for the specified attack path were successfully retrieved.");

            final String URI = ProjectProperties.getProperty("bus-uri");
            final String topic = TopicName.APPLICABLE_MITIGATIONS.getTopic();

            try {
                TopicMessageSender.sendTo(URI, topic, response.toString());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("[GET:/attack-path/" + id + "/remediations] Error when contacting the information bus: " + topic);
                e.printStackTrace();
            }

            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(TopicName.APPLICABLE_MITIGATIONS, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediations, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/{id}/remediation/{id-remediation}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_ID_remediation_ID(@Context HttpServletRequest request, @PathParam("id") int id, @PathParam("id-remediation") int id_remediation) throws Exception {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Check if the remediations database is empty.
            Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));
            if (db == null) {
                Logger.getAnonymousLogger().severe("The system database object is null");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the system database object is null.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            // Check if the requested attack path actually exists.
            int attackPathsSize = monitoring.getAttackPathList().size();
            if ((id < 0) || (id >= attackPathsSize)) {
                String msg = "The attack path ID=" + id + " is invalid. There are only " + attackPathsSize + " attack paths generated ID=(0 to " + (attackPathsSize - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the list of remediations.
            List<DeployableRemediation> remediations = monitoring.getAttackPathList().get(id).getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());
            int numberRemediations = remediations.size();
            if ((id_remediation < 0) || (id_remediation >= numberRemediations)) {
                String msg = "The remediation ID=" + id_remediation + " is invalid. There are only " + numberRemediations + " remediations for that path ID=(0 to " + (numberRemediations - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the attack graph after the specified remediation has been applied.
            DeployableRemediation remediation = remediations.get(id_remediation);
            AttackGraph simulatedAttackGraph = null;
            try {
                // Generate the new attack graph.
                simulatedAttackGraph = monitoring.getAttackGraph().clone();
                for (int i = 0; i < remediation.getActions().size(); i++) {
                    Vertex vertexToDelete = remediation.getActions().get(i).getRemediationAction().getRelatedVertex();
                    simulatedAttackGraph.deleteVertex(simulatedAttackGraph.vertices.get(vertexToDelete.id));
                }
                AttackPathManagement.scoreAttackPaths(simulatedAttackGraph, monitoring.getAttackGraph().getNumberOfVertices());

                // Generate the graph JSON.
                payload.put("attack_graph", mulval_attack_graph(simulatedAttackGraph.toDomElement(), simulatedAttackGraph));
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The new attack graph was successfully generated.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response);
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("Unknown exception");
                e.printStackTrace();
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the simulated attack graph couldn't be generated.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + ", Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-path/{id}/remediation/{id-remediation}/validate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackpath_ID_remediation_ID_validate(@Context HttpServletRequest request, @PathParam("id") int id, @PathParam("id-remediation") int id_remediation) throws Exception {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            // Check if the remediations database is empty.
            Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));
            if (db == null) {
                Logger.getAnonymousLogger().severe("The system database object is null");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the system database object is null.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            // Check if the requested attack path actually exists.
            int attackPathsSize = monitoring.getAttackPathList().size();
            if ((id < 0) || (id >= attackPathsSize)) {
                String msg = "The attack path ID=" + id + " is invalid. There are only " + attackPathsSize + " attack paths generated ID=(0 to " + (attackPathsSize - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Get the list of remediations.
            List<DeployableRemediation> remediations = monitoring.getAttackPathList().get(id).getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());
            int numberRemediations = remediations.size();
            if ((id_remediation < 0) || (id_remediation >= numberRemediations)) {
                String msg = "The remediation ID=" + id_remediation + " is invalid. There are only " + numberRemediations + " remediations for that path ID=(0 to " + (numberRemediations - 1) + ").";
                Logger.getAnonymousLogger().severe(msg);

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, msg);
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.BAD_REQUEST);
            }

            // Validate the application of the remediation.
            DeployableRemediation deployableRemediation = remediations.get(id_remediation);
            try {
                deployableRemediation.validate(monitoring.getInformationSystem());
            } catch (Exception e) {
                Logger.getAnonymousLogger().warning("Unknown exception");
                e.printStackTrace();

                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "Internal error, the validation of the specified remediation action wasn't possible.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.INTERNAL_SERVER_ERROR);
            }

            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The validation of the specified remediation action was successful.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-path/" + id + "/remediation/" + id_remediation + "/validate, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/attack-graph/reduced")
    @Produces(MediaType.APPLICATION_JSON)
    public Response GET_attackgraph_reduced(@Context HttpServletRequest request) {
        Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/attack-graph/reduced, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());

        try {
            JSONObject response;
            JSONObject payload = new JSONObject();

            // Check to see if the system has been initialized.
            Monitoring monitoring = (Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring");
            if (monitoring == null) {
                Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");
                response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.ERROR, "The monitoring object is empty.");
                Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/reduced, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
                return RestApplication.returnJsonObject(request, response, Response.Status.PRECONDITION_FAILED);
            }

            payload.put("attack_graph", mulval_attack_graph(monitoring.getAttackGraph().toDomElement(), monitoring.getAttackGraph()));
            response = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, payload, ResultJSONStructureStatus.OK, "The reduced MulVAL attack graph was successfully retrieved.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/reduced, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            JSONObject responseError = RestApplication.prepareResponseJSONStructure(InternalTopicName.TEST, new JSONObject(), ResultJSONStructureStatus.ERROR, "Internal error, check the iRG Server logs for the stacktrace.");
            Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/attack-graph/reduced, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
            return RestApplication.returnJsonObject(request, responseError, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}
