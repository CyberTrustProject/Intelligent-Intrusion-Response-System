/****************************************************************************************
 * This file is part of FIWARE CyberCAPTOR,                                             *
 * instance of FIWARE Cyber Security Generic Enabler                                    *
 * Copyright (C) 2012-2015  Thales Services S.A.S.,                                     *
 * 20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           *
 *                                                                                      *
 * FIWARE CyberCAPTOR is free software; you can redistribute                            *
 * it and/or modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 3 of the License,       *
 * or (at your option) any later version.                                               *
 *                                                                                      *
 * FIWARE CyberCAPTOR is distributed in the hope                                        *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied           *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                                         *
 *                                                                                      *
 * You should have received a copy of the GNU General Public License                    *
 * along with FIWARE CyberCAPTOR.                                                       *
 * If not, see <http://www.gnu.org/licenses/>.                                          *
 ****************************************************************************************/
package org.fiware.cybercaptor.server.rest;

import eu.cybertrust.queuemanagement.TopicSubscriptionManager;
import org.apache.commons.io.IOUtils;
import org.fiware.cybercaptor.server.api.AttackPathManagement;
import org.fiware.cybercaptor.server.api.IDMEFManagement;
import org.fiware.cybercaptor.server.api.InformationSystemManagement;
import org.fiware.cybercaptor.server.attackgraph.*;
import org.fiware.cybercaptor.server.database.Database;
import org.fiware.cybercaptor.server.informationsystem.InformationSystem;
import org.fiware.cybercaptor.server.monitoring.Monitoring;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.properties.ProtectedNetworks;
import org.fiware.cybercaptor.server.remediation.BlockNode;
import org.fiware.cybercaptor.server.remediation.DeployableRemediation;
import org.fiware.cybercaptor.server.system.SystemInformation;
import org.fiware.cybercaptor.server.system.integrationbus.topologyconfig.TopologyConfigMessageConsumer;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.json.*;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.DataOutputStream;
import java.io.FileOutputStream;

/**
 * JSON Rest API, main API, since the XML API has been depreciated.
 *
 * @author Francois -Xavier Aguessy
 */
@Path("/json/")
public class RestJsonAPI {

    /**
     * Generates the attack graph and initializes the main objects for other API calls
     * (database, attack graph, attack paths,...)
     * 
     * This call uses the CyberCAPTOR Data Extraction module to generate the FIWARE XML topology
     * using data from disk.
     *
     * @param request the HTTP request
     * @return the HTTP response
     * @throws Exception
     */
    @GET
    @Path("initialize")
    @Produces(MediaType.APPLICATION_JSON)
    public Response initialise(@Context HttpServletRequest request) throws Exception {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        String databasePath = ProjectProperties.getProperty("database-path");
        String topologyFilePath = ProjectProperties.getProperty("topology-path");
        
        // Generate the topology from the existing files on disk.
        try {
            Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Generating topology from data on disk " + topologyFilePath);
            InformationSystemManagement.generateXmlTopologyFromDiskFiles();
        }
        catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "[ERROR] Couldn't generate the topology XML file from data on disk"); 
        }
        
        try {
            initializationProcedure(request, databasePath, topologyFilePath, costParametersFolderPath);
        }
        catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack graph is empty");
        }
        
        return RestApplication.returnJsonObject(request, new JSONObject().put("status", "Loaded"));
    }

    /**
     * OPTIONS call necessary for the Access-Control-Allow-Origin of the POST
     *
     * @return the HTTP response
     */
    @OPTIONS
    @Path("/initialize")
    public Response initializeOptions(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Generates the attack graph and initializes the main objects for other API calls
     * (database, attack graph, attack paths,...).
     * Load the objects from the POST XML file describing the whole network topology
     *
     * This call loads the FIWARE XML topology from the POST data sent.
     * 
     * @param request the HTTP request
     * @return the HTTP response
     * @throws Exception
     */
    @POST
    @Path("/initialize")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response initializeFromXMLText(@Context HttpServletRequest request, String xmlString) throws Exception {
        String costParametersFolderPath = ProjectProperties.getProperty("cost-parameters-path");
        String databasePath = ProjectProperties.getProperty("database-path");
        String topologyFilePath = ProjectProperties.getProperty("topology-path");
        
        // Store the given XML topology to disk.
        try {
            Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Storing topology in " + topologyFilePath);
            storeXMLTopology(xmlString, topologyFilePath);
        }
        catch (Exception e) {
            Logger.getAnonymousLogger().log(Level.INFO, "[ERROR] Failed to store topology in " + topologyFilePath);
            return RestApplication.returnErrorMessage(request, "[ERROR] The input text string is empty.");
        }

        try {
            initializationProcedure(request, databasePath, topologyFilePath, costParametersFolderPath);
        }
        catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack graph is empty");
        }

        return RestApplication.returnJsonObject(request, new JSONObject().put("status", "Loaded"));
    }
    
    /**
     * Stores the provided FIWARE XML topology to a file.
     *
     * @param topologyXML the FIWARE XML topology, provided by the user
     * @param topologyFilePath the path to store the FIWARE XML topology
     * @throws IllegalArgumentException
     */
    void storeXMLTopology(String topologyXML, String topologyFilePath) throws Exception {
        if (topologyXML == null || topologyXML.isEmpty())
            throw new IllegalArgumentException("[ERROR] The input text string is empty.");
        
        PrintWriter out = new PrintWriter(topologyFilePath);
        out.print(topologyXML);
        out.close();
    }

    /**
     * The main initialization procedure.
     * Common functionality of all /initialize RestAPI calls.
     * 
     * The FIWARE XML topology must be generated/written to a file (as specified by the
     * configuration file variable topology-path) before calling this function.
     * The topology is loaded in memory, the MulVAL input is generated, MulVAL gets called,
     * the attack paths are discovered and the attack graph is scored.
     *
     * @param databasePath path to vulnerability-remediation-database.db Sqlite3 database
     * @param topologyFilePath path to FIWARE XML topology, as provided by the caller or as generated from data on disk
     * @param costParametersFolderPath path to cost-parameters directory, storing the cost parameters as XML files
     * @throws MulvalAttackGraphEmptyException
     */
    private void initializationProcedure(HttpServletRequest request, String databasePath, String topologyFilePath, String costParametersFolderPath) throws Exception {
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Loading vulnerability and remediation database");
        Database database = new Database(databasePath);
        
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Loading FIWARE XML topology " + topologyFilePath);
        InformationSystem informationSystem = InformationSystemManagement.loadTopologyXMLFile(topologyFilePath, database);
        
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Preparing MulVAL inputs");
        File mulvalInputFile = new File(ProjectProperties.getProperty("mulval-input"));
        informationSystem.exportToMulvalDatalogFile(mulvalInputFile.getAbsolutePath());
        
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Executing MulVAL");
        // Set the filename of the MulVAL attack graph XML output.
        String outputFolderPath = ProjectProperties.getProperty("output-path");
        String attackGraphXMLOutput = "/attkgrph";
        File mulvalOutputFile = new File(outputFolderPath + attackGraphXMLOutput + ".xml");
        if (mulvalOutputFile.exists()) {
            mulvalOutputFile.delete();
        }
        AttackGraph attackGraph = InformationSystemManagement.executeMulval(mulvalInputFile, mulvalOutputFile, attackGraphXMLOutput);
        attackGraph.loadMetricsFromTopology(informationSystem);

        

        if (attackGraph == null)
            throw new MulvalEmptyAttackGraphException("[ERROR] The attack graph is empty");

        Logger.getAnonymousLogger().log(Level.INFO, "COMPUTE_PARENTS_AND_CHILDREN");
        attackGraph.computeAllParentsAndChildren();

        
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Launch scoring function");
        attackGraph.loadMetricsFromTopology(informationSystem);

        try {
            Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Vertex to host associations.");
            attackGraph.vertexToHostAssociations = VertexHostAssociation.AssociateHostsToVertices(informationSystem, (MulvalAttackGraph) attackGraph);
            attackGraph.enrichVertexInfo(informationSystem);
        } catch (Exception e) {
            e.printStackTrace();
        }


        // Send the attack graph to the iIRS.
        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] Generating the attack graph JSON.");
        JSONObject attackGraphJson = null;
        try {
            attackGraphJson = RestJsonAPIv2.mulval_attack_graph(attackGraph.toDomElement(), attackGraph);
        } catch (JSONException e) {
            e.printStackTrace();
            throw e;
        }

        // Create a new thread to send the attack graph to the iRE.
        // To avoid the client hanging in case the iRE Server isn't responding.
        RestApplication.print_message(Level.INFO, "Sending the attack graph JSON to the iRE Server.");
        final String ireUrl = ProjectProperties.getProperty("ire-url-topology");
        final JSONObject finalAttackGraphJson = attackGraphJson;
        Thread ireConnectThread = new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        RestApplication.print_message(Level.INFO, "Thread created to send the attack graph to iRE.");

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

                                RestApplication.print_message(Level.INFO, "Attack graph posted to the iRE. Response code: " + responseCode);
                            } else {
                                RestApplication.print_message(Level.INFO, "Cannot connect to the iRE. Attack graph not posted.");
                            }
                        }
                        catch (Exception e) {
                            RestApplication.print_message(Level.INFO, "Cannot connect to the iRE. Attack graph not posted.");
                            e.printStackTrace();
                        }

                        RestApplication.print_message(Level.INFO, "Thread finished.");
                    }
                }
        );
        ireConnectThread.start();

        // TODO: RESTORE ATTACK PATHS
//        Logger.getAnonymousLogger().log(Level.INFO, "[INFO] " + attackPaths.size() + " attack paths scored");
        Monitoring monitoring = new Monitoring(costParametersFolderPath);
//        monitoring.setAttackPathList(attackPaths);
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
                        RestApplication.print_message(Level.INFO, topic + " Thread created to subscribe to the bus.");

                        try {
                            TopologyConfigMessageConsumer consumer = new TopologyConfigMessageConsumer(topic, "POST", "/topology/config");
                            TopicSubscriptionManager.subscribeTo(ProjectProperties.getProperty("bus-uri"), topic, consumer);
                        }
                        catch (Exception e) {
                            e.printStackTrace();
                        }

                        RestApplication.print_message(Level.INFO, topic + " Thread finished, stopped listening.");
                    }
                }
        );
        bus_topic_config.start();
    }
    
    /**
     * Generates the attack graph and initializes the main objects for other API calls
     * (database, attack graph, attack paths,...).
     * Load the objects from the XML file POST through a form describing the whole network topology
     *
     * @param request             the HTTP request
     * @param uploadedInputStream The input stream of the XML file
     * @param fileDetail          The file detail object
     * @param body                The body object relative to the XML file
     * @return the HTTP response
     * @throws Exception
     */
    @POST
    @Path("/initialize")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response initializeFromXMLFile(@Context HttpServletRequest request,
                                          @FormDataParam("file") InputStream uploadedInputStream,
                                          @FormDataParam("file") FormDataContentDisposition fileDetail,
                                          @FormDataParam("file") FormDataBodyPart body) throws Exception {

        if (!body.getMediaType().equals(MediaType.APPLICATION_XML_TYPE) && !body.getMediaType().equals(MediaType.TEXT_XML_TYPE)
                && !body.getMediaType().equals(MediaType.TEXT_PLAIN_TYPE))
            return RestApplication.returnErrorMessage(request, "[ERROR] The file is not an XML file");
        String xmlFileString = IOUtils.toString(uploadedInputStream, "UTF-8");

        return initializeFromXMLText(request, xmlFileString);

    }

    /**
     * Get the XML topology
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/topology")
    @Produces(MediaType.APPLICATION_XML)
    public Response getTopology(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return Response.ok("[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?").build();
        }
        return Response.ok(new XMLOutputter(Format.getPrettyFormat()).outputString(monitoring.getInformationSystem().toDomXMLElement())).build();
    }

    /**
     * Get the hosts list
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("host/list")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getHostList(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }
        return RestApplication.returnJsonObject(request, monitoring.getInformationSystem().getHostsListJson());
    }

    @OPTIONS
    @Path("/host/list")
    public Response setHostListOptions(@Context HttpServletRequest request) {
        return RestApplication.returnJsonObject(request, new JSONObject());
    }

    /**
     * Post the hosts list with their new security requirements
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @POST
    @Path("host/list")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setHostList(@Context HttpServletRequest request, String jsonString) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }
        JSONObject json = new JSONObject(jsonString);
        try {
            InformationSystemManagement.loadHostsSecurityRequirementsFromJson(monitoring, json);
            return RestApplication.returnJsonObject(request, new JSONObject());
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }


    }

    /**
     * Get the attack paths list
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/list")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getList(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        Element attackPathsXML = AttackPathManagement.getAttackPathsXML(monitoring);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(attackPathsXML)));

    }

    /**
     * Get the number of attack paths
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/number")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNumber(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return RestApplication.returnJsonObject(request, new JSONObject().put("number", monitoring.getAttackPathList().size()));
    }

    /**
     * Get one attack path (id starting from 0)
     *
     * @param request the HTTP Request
     * @param id      the id of the attack path to get
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackPath(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        Element attackPathXML = AttackPathManagement.getAttackPathXML(monitoring, id);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(attackPathXML)));
    }

    /**
     * Get one attack path (id starting from 0) in its topological form
     *
     * @param request the HTTP Request
     * @param id      the id of the attack path to get
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTopologicalAttackPath(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        return RestApplication.returnJsonObject(request, AttackPathManagement.getAttackPathTopologicalJson(monitoring, id));
    }

    /**
     * Compute and return the remediations for an attack path
     *
     * @param request the HTTP Request
     * @param id      the identifier of the attack path for which the remediations will be computed
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/remediations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackPathRemediations(@Context HttpServletRequest request, @PathParam("id") int id) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        if (db == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The database object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        Element remediationXML = AttackPathManagement.getRemediationXML(monitoring, id, db);
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());

        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(remediationXML)));
    }

    /**
     * Simulate the remediation id_remediation of the path id, and compute the new attack graph
     *
     * @param request        the HTTP Request
     * @param id             the identifier of the attack path for which the remediations will be computed
     * @param id_remediation the identifier of the remediation to simulate
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/remediation/{id-remediation}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response simulateRemediationInAttackGraph(@Context HttpServletRequest request, @PathParam("id") int id, @PathParam("id-remediation") int id_remediation) throws Exception {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        if (db == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The database object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        List<DeployableRemediation> remediations = monitoring.getAttackPathList().get(id).getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());

        int numberRemediations = remediations.size();

        if (id_remediation >= numberRemediations) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The remediation " + id_remediation + " does not exist. There are only" +
                    numberRemediations + " remediations (0 to " +
                    (numberRemediations - 1) + ")");
        }
        DeployableRemediation deployableRemediation = remediations.get(id_remediation);

        AttackGraph simulatedAttackGraph;

        try {
            simulatedAttackGraph = monitoring.getAttackGraph().clone();

            for (int i = 0; i < deployableRemediation.getActions().size(); i++) {
                Vertex vertexToDelete = deployableRemediation.getActions().get(i).getRemediationAction().getRelatedVertex();
                simulatedAttackGraph.deleteVertex(simulatedAttackGraph.vertices.get(vertexToDelete.id));
            }

            AttackPathManagement.scoreAttackPaths(simulatedAttackGraph, monitoring.getAttackGraph().getNumberOfVertices());

            Element attackGraphXML = simulatedAttackGraph.toDomElement();
            XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
            return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(attackGraphXML)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return RestApplication.returnErrorMessage(request, "[ERROR] Error during the simulation of the remediation.");

    }

    /**
     * Validate that the remediation id_remediation of the path id has been applied
     *
     * @param request        the HTTP Request
     * @param id             the identifier of the attack path for which the remediations have been computed
     * @param id_remediation the identifier of the remediation to validate
     * @return the HTTP Response
     */
    @GET
    @Path("attack_path/{id}/remediation/{id-remediation}/validate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateRemediationInAttackGraph(@Context HttpServletRequest request, @PathParam("id") int id, @PathParam("id-remediation") int id_remediation) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));
        Database db = ((Database) request.getSession(true).getServletContext().getAttribute("database"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        if (db == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The database object is empty. Did you forget to " +
                    "initialize it ?");
        }

        int numberAttackPaths = monitoring.getAttackPathList().size();

        if (id >= numberAttackPaths) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The attack path " + id + " does not exist. There are only" +
                    numberAttackPaths + " attack paths (0 to " +
                    (numberAttackPaths - 1) + ")");
        }

        List<DeployableRemediation> remediations;
        try {
            remediations = monitoring.getAttackPathList().get(id).getDeployableRemediations(monitoring.getInformationSystem(), db.getConn(), monitoring.getPathToCostParametersFolder());
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "[ERROR] Error during the computation of the remediations:" + e.getMessage());
        }

        int numberRemediations = remediations.size();

        if (id_remediation >= numberRemediations) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The remediation " + id_remediation + " does not exist. There are only" +
                    numberRemediations + " remediations (0 to " +
                    (numberRemediations - 1) + ")");
        }
        DeployableRemediation deployableRemediation = remediations.get(id_remediation);

        try {
            deployableRemediation.validate(monitoring.getInformationSystem());
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, "[ERROR] Error during the validation of the remediations:" + e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "[INFO] The remediation has been validated.");

    }

    /**
     * Get the whole attack graph
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackGraph(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        Element attackGraphXML = monitoring.getAttackGraph().toDomElement();
        XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
        return RestApplication.returnJsonObject(request, XML.toJSONObject(output.outputString(attackGraphXML)));
    }

    /**
     * Get the attack graph score
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph/score")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAttackGraphScore(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return RestApplication.returnJsonObject(request, new JSONObject().put("score", monitoring.getAttackGraph().globalScore));
    }

    /**
     * Get the topological representation of the whole attack graph
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("attack_graph/topological")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTopologicalAttackGraph(@Context HttpServletRequest request) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return RestApplication.returnJsonObject(request, AttackPathManagement.getAttackGraphTopologicalJson(monitoring));
    }


    /**
     * Receive alerts in IDMEF format and add them into a local queue file,
     * before releasing them when the client requests it.
     *
     * @param request             the HTTP request
     * @param uploadedInputStream The input stream of the IDMEF XML file
     * @param fileDetail          The file detail object
     * @param body                The body object relative to the XML file
     * @return the HTTP response
     * @throws Exception
     */
    @POST
    @Path("/idmef/add")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response addIDMEFAlerts(@Context HttpServletRequest request,
                                   @FormDataParam("file") InputStream uploadedInputStream,
                                   @FormDataParam("file") FormDataContentDisposition fileDetail,
                                   @FormDataParam("file") FormDataBodyPart body) throws Exception {

        if (!body.getMediaType().equals(MediaType.APPLICATION_XML_TYPE) && !body.getMediaType().equals(MediaType.TEXT_XML_TYPE)
                && !body.getMediaType().equals(MediaType.TEXT_PLAIN_TYPE))
            return RestApplication.returnErrorMessage(request, "[ERROR] The file is not an XML file");

        String xmlFileString = IOUtils.toString(uploadedInputStream, "UTF-8");
        return addIDMEFAlertsFromXMLText(request, xmlFileString);
    }

    /**
     * Receive alerts in IDMEF format and add them into a local queue file,
     * before releasing them when the client requests it.
     *
     * @param request the HTTP request
     * @return the HTTP response
     * @throws Exception
     */
    @POST
    @Path("/idmef/add")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addIDMEFAlertsFromXMLText(@Context HttpServletRequest request, String xmlString) throws Exception {
        if (xmlString == null || xmlString.isEmpty())
            return RestApplication.returnErrorMessage(request, "[ERROR] The input text string is empty.");

        IDMEFManagement.loadIDMEFAlertsFromXML(xmlString);
        return RestApplication.returnSuccessMessage(request, "[INFO] IDMEF alerts added successfully");
    }

    /**
     * Get alerts in JSON format and set them as "sent" into a local queue file.
     *
     * @param request the HTTP Request
     * @return the HTTP Response
     */
    @GET
    @Path("/idmef/alerts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAlerts(@Context HttpServletRequest request) throws IOException, ClassNotFoundException {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));

        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to " +
                    "initialize it ?");
        }

        return RestApplication.returnJsonObject(request, IDMEFManagement.getAlerts(monitoring.getInformationSystem()));
    }

    /**
     * Generate the hosts-interfaces.csv on disk.
     * Any existing data will be overwritten.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/hosts-interfaces")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateHostsInterfacesCsv(@Context HttpServletRequest request, String jsonString) {
        String hostsInterfacesFilePath = ProjectProperties.getProperty("host-interfaces-path");
        ArrayList<String> csvLines = new ArrayList<String>();

        ServletContext context = request.getSession().getServletContext();
        if (context.getAttribute("netip") == null) {
            context.setAttribute("netip", new ProtectedNetworks());
        }
        ProtectedNetworks protectedNetworks = (ProtectedNetworks)context.getAttribute("netip");

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

                if(protectedNetworks.belongsToNetwork(ip_address)) {
                    csvLines.add(line);
                }
            }

        } catch (JSONException e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        // Generate the CSV file.
        try {
            PrintWriter writer = new PrintWriter(hostsInterfacesFilePath);
            for (String l : csvLines) {
                writer.println(l);
            }
            writer.close();
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "hosts-interfaces.csv generated successfully.");
    }

    /**
     * Generate the vlans.csv on disk.
     * Any existing data will be overwritten.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/vlans")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateVlansCsv(@Context HttpServletRequest request, String jsonString) {
        String vlansFilePath = ProjectProperties.getProperty("vlans-path");
        ArrayList<String> csvLines = new ArrayList<String>();

        ServletContext context = request.getSession().getServletContext();
        if (context.getAttribute("netip") == null) {
            context.setAttribute("netip", new ProtectedNetworks());
        }
        ProtectedNetworks protectedNetworks = (ProtectedNetworks)context.getAttribute("netip");

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

                if(protectedNetworks.belongsToNetwork(gateway)) {
                    csvLines.add(line);
                }
            }

        } catch (JSONException e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        // Generate the CSV file.
        try {
            PrintWriter writer = new PrintWriter(vlansFilePath);
            for (String l : csvLines) {
                writer.println(l);
            }
            writer.close();
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "vlans.csv generated successfully.");
    }

    /**
     * Generate the flow-matrix.csv on disk.
     * Any existing data will be overwritten.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/flow-matrix")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateFlowMatrixCsv(@Context HttpServletRequest request, String jsonString) {
        String flowMatrixFilePath = ProjectProperties.getProperty("flow-matrix-path");
        ArrayList<String> csvLines = new ArrayList<String>();

        ServletContext context = request.getSession().getServletContext();
        if (context.getAttribute("netip") == null) {
            context.setAttribute("netip", new ProtectedNetworks());
        }
        ProtectedNetworks protectedNetworks = (ProtectedNetworks)context.getAttribute("netip");

        // Parse the JSON.
        try {
            JSONArray flowMatrixJsonArray = new JSONArray(jsonString);

            for (int i = 0; i < flowMatrixJsonArray.length(); i++) {
                JSONObject flowMatrixJsonObject = flowMatrixJsonArray.getJSONObject(i);

                String source = flowMatrixJsonObject.getString("source");
                if(!protectedNetworks.belongsToNetwork(source)) {
                    source = "internet";
                }

                String destination = flowMatrixJsonObject.getString("destination");
                if(!protectedNetworks.belongsToNetwork(destination)) {
                    destination = "internet";
                }

                String source_port = flowMatrixJsonObject.getString("source_port");
                String destination_port = flowMatrixJsonObject.getString("destination_port");
                String protocol = flowMatrixJsonObject.getString("protocol");

                String line = "\"" + source + "\";\"" + destination + "\";\"" + source_port + "\";\"" + destination_port + "\";\"" + protocol + "\"";
                csvLines.add(line);
            }

        } catch (JSONException e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        // Generate the CSV file.
        try {
            PrintWriter writer = new PrintWriter(flowMatrixFilePath);
            for (String l : csvLines) {
                writer.println(l);
            }
            writer.close();
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "flow-matrix.csv generated successfully.");
    }

    /**
     * Generate the routing.csv on disk.
     * Any existing data will be overwritten.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/routing")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateRoutingCsv(@Context HttpServletRequest request, String jsonString) {
        String routingFilePath = ProjectProperties.getProperty("routing-path");
        ArrayList<String> csvLines = new ArrayList<String>();

        ServletContext context = request.getSession().getServletContext();
        if (context.getAttribute("netip") == null) {
            context.setAttribute("netip", new ProtectedNetworks());
        }
        ProtectedNetworks protectedNetworks = (ProtectedNetworks)context.getAttribute("netip");

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

                if(protectedNetworks.belongsToNetwork(gateway)) {
                    csvLines.add(line);
                }
            }

        } catch (JSONException e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }


        // Generate the CSV file.
        try {
            PrintWriter writer = new PrintWriter(routingFilePath);
            for (String l : csvLines) {
                writer.println(l);
            }
            writer.close();
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "routing.csv generated successfully.");
    }


    /**
     * Receives a list of attack graph nodes to be blocked.
     * Responds with the relevant (if any) firewall rules.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("attack_graph/block_nodes")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateFirewallRulesToBlockNodes(@Context HttpServletRequest request, String jsonString) {
        Monitoring monitoring = ((Monitoring) request.getSession(true).getServletContext().getAttribute("monitoring"));
        if (monitoring == null) {
            return RestApplication.returnErrorMessage(request, "[ERROR] The monitoring object is empty. Did you forget to initialize it?");
        }

        // Load the nodes to be blocked.
        ArrayList<Integer> nodesToBlock = new ArrayList<Integer>();
        try {
            JSONArray nodesJsonArray = new JSONArray(jsonString);

            for (int i = 0; i < nodesJsonArray.length(); i++) {
                JSONObject o = nodesJsonArray.getJSONObject(i);
                nodesToBlock.add(Integer.valueOf(o.getInt("node")));
            }
        } catch (JSONException e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        // The V1 API is deprecated, check the V2 call.
        return RestApplication.returnSuccessMessage(request, "TEMPORARY RESPONSE!");
    }


    /**
     * Generates a OpenVAS XML report from the received nmap JSON scan results.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/vuln-scan-report")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateOpenVASScanReport(@Context HttpServletRequest request, String jsonString) {
        Element root_root = new Element("report");
        Element root = new Element("report");
        root_root.addContent(root);
        Element results = new Element("results");
        root.addContent(results);
        JSONObject jsonReport;

        try {
            jsonReport = new JSONObject(jsonString);
        } catch (JSONException e) {
            // Malformed JSON, terminate.
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        // For every host.
        for (Object key : jsonReport.keySet()) {
            JSONObject hostObject;

            try {
                hostObject = jsonReport.getJSONObject((String) key);
            } catch (JSONException e) {
                // Malformed JSON, terminate.
                return RestApplication.returnErrorMessage(request, e.getMessage());
            }

            // Get its IP address (always present).
            String hostString = hostObject.getJSONObject("addresses").getString("ipv4");

            // Try to get the open TCP ports (optional).
            JSONObject hostTcpResults = null;
            try {
                hostTcpResults = hostObject.getJSONObject("tcp");
            } catch (JSONException e) {
                // Just report that there aren't any open TCP ports and continue.
                //System.out.println(e.getMessage());
            }
            if (hostTcpResults != null) {
                for (Object portKey : hostTcpResults.keySet()) {
                    JSONObject portObject;

                    String nameString = "";
                    try {
                        portObject = hostTcpResults.getJSONObject((String) portKey);
                        nameString = portObject.getString("product");
                        if (!nameString.isEmpty()) {
                            nameString += " ";
                        }
                        nameString += portObject.getString("name");
                    } catch (JSONException e) {
                        // Malformed JSON, terminate.
                        return RestApplication.returnErrorMessage(request, e.getMessage());
                    }

                    String portString = (String) portKey;
                    ArrayList<String> cveList = new ArrayList<String>();

                    // Try to get information about the vulnerable service (optional).
                    try {
                        String vulnersReport = portObject.getJSONObject("script").getString("vulners");
                        String[] vulners = vulnersReport.split("\n\t");

                        String cpe = vulners[0].trim();
                        for (int i = 1; i < vulners.length; i++) {
                            String cve = vulners[i].split("\t\t")[0].trim();
                            cveList.add(cve);
                        }
                    } catch (JSONException e) {
                        // Just report that there aren't any vulnerabilities and continue.
                        //System.out.println(e.getMessage());
                    }

                    Element result = new Element("result");
                    results.addContent(result);

                    Element name = new Element("name");
                    name.setText(nameString);
                    result.addContent(name);

                    Element host = new Element("host");
                    host.setText(hostString);
                    result.addContent(host);

                    Element port = new Element("port");
                    port.setText(portString + "/tcp");
                    result.addContent(port);

                    if(!cveList.isEmpty()) {
                        for (String cveString : cveList) {
                            Element nvt = new Element("nvt");
                            result.addContent(nvt);
                            Element cve = new Element("cve");
                            cve.setText(cveString);
                            nvt.addContent(cve);
                        }
                    }
                }
            }

            // Try to get the open UDP ports (optional).
        }

        try {
            String vulnScanReportFilePath = ProjectProperties.getProperty("vulnerability-scan-path");
            XMLOutputter output = new XMLOutputter(Format.getPrettyFormat());
            //output.output(root, System.out);
            output.output(root_root, new FileOutputStream(vulnScanReportFilePath));
        } catch (Exception e) {
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "Vulnearbility scanner report generated successfully.");
    }

    /**
     * Generates a OpenVAS XML report from the received nmap JSON scan results.
     *
     * @param request the HTTP Request
     * @param jsonString the file contents to be saved on disk
     * @return the HTTP Response
     */
    @POST
    @Path("topology/net-ip")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setConsideredNetworks(@Context HttpServletRequest request, String jsonString) {
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
            return RestApplication.returnErrorMessage(request, e.getMessage());
        }

        return RestApplication.returnSuccessMessage(request, "");
    }
}
