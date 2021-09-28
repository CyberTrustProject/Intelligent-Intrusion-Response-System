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

import com.fasterxml.uuid.Generators;
import eu.cybertrust.cryptoutils.SignatureOperations;
import org.bouncycastle.util.io.pem.PemReader;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.json.JSONObject;

import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Response;

@ApplicationPath("/rest")
public class RestApplication extends ResourceConfig {
    /**
     * Register the package of the rest application
     */
    public RestApplication() {
        packages("org.fiware.cybercaptor.server.rest");
        packages("org.glassfish.jersey.examples.multipart");
        register(MultiPartFeature.class);
    }

    /**
     * Returns the {@link javax.ws.rs.core.Response} object from a {@link org.json.JSONObject}
     *
     * @param jsonObject the jsonObject to return
     * @return the relative {@link javax.ws.rs.core.Response} object
     */
    public static Response returnJsonObject(HttpServletRequest request, JSONObject jsonObject) {
        return returnJsonObject(request, jsonObject, Response.Status.OK);
    }

    public static Response returnJsonObject(HttpServletRequest request, JSONObject jsonObject, Response.Status status) {
        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("Responded with: HTTP " + status.getStatusCode() + " " + status.getReasonPhrase());
            Logger.getAnonymousLogger().info("[OUTPUT] [JSON] Response: " + jsonObject);
        }

        // client's origin
        String clientOrigin = request.getHeader("origin");

        return Response.ok(jsonObject.toString())
                .header("Access-Control-Allow-Origin", clientOrigin)
                .header("Access-Control-Allow-Headers", "origin, content-type, accept, authorization")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
                .header("Access-Control-Max-Age", "1209600")
                .status(status)
                .build();
    }

    /**
     * Returns an error message, in a {@link org.json.JSONObject} ({error:"the error message"}
     *
     * @param errorMessage the error message to return
     * @return the {@link javax.ws.rs.core.Response} to this {@link org.json.JSONObject}
     */
    public static Response returnErrorMessage(HttpServletRequest request, String errorMessage) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error", errorMessage);

        return returnJsonObject(request, jsonObject);
    }

    /**
     * Returns a success message, in a {@link org.json.JSONObject} ({success:"the success message"}
     *
     * @param successMessage the sucess message to return
     * @return the {@link javax.ws.rs.core.Response} to this {@link org.json.JSONObject}
     */
    public static Response returnSuccessMessage(HttpServletRequest request, String successMessage) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("success", successMessage);

        return returnJsonObject(request, jsonObject);
    }

    // -----------------------------------------------------------------------------------------------------------------

    private static JSONObject prepareResponseJSONStructure(String topic, JSONObject payload, ResultJSONStructureStatus status, String message, String cor_id) {
        JSONObject structure = new JSONObject();

        JSONObject header = new JSONObject();
        structure.put("header", header);
        header.put("source", ProjectProperties.getProperty("smart-device-module-id"));
        header.put("timestamp", (System.currentTimeMillis() / 1000L));
        header.put("msg_topic", topic);
        UUID uuid = Generators.randomBasedGenerator().generate();
        header.put("msg_id", uuid.toString());
        if(!cor_id.isEmpty() && !(cor_id == null)) {
            header.put("cor_id", cor_id);
        }

        JSONObject metadata = new JSONObject();
        metadata.put("status", status.name());
        metadata.put("message", message);
        metadata.put("api", ProjectProperties.getProperty("api-version"));

        if (payload == null) {
            JSONObject emptyPayload = new JSONObject();
            emptyPayload.put("metadata", metadata);
            structure.put("payload", emptyPayload);
        }
        else {
            payload.put("metadata", metadata);
            structure.put("payload", payload);
        }

        return structure;
    }

    public static JSONObject prepareResponseJSONStructure(InternalTopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message) {
        return prepareResponseJSONStructure(topic.toString(), payload, status, message, "");
    }

    public static JSONObject prepareResponseJSONStructure(TopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message) {
        return prepareResponseJSONStructure(topic.toString(), payload, status, message, "");
    }

    public static JSONObject prepareResponseJSONStructure(InternalTopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message, String cor_id) {
        return prepareResponseJSONStructure(topic.toString(), payload, status, message, cor_id);
    }

    public static JSONObject prepareResponseJSONStructure(TopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message, String cor_id) {
        return prepareResponseJSONStructure(topic.toString(), payload, status, message, cor_id);
    }

    private static void signJSONStructure(JSONObject structure) throws Exception {
        JSONObject trailer = null;
        if (!structure.has("trailer")) {
            trailer = new JSONObject();
            structure.put("trailer", trailer);
        }
        else {
            trailer = structure.getJSONObject("trailer");
        }

        String filePath = ProjectProperties.getProperty("crypto-self-key");
        File file = new File(filePath);
        PemReader PEMreader = new PemReader(new FileReader(file));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(PEMreader.readPemObject().getContent());
        RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);

        JSONObject toSign = new JSONObject();
        toSign.put("header", structure.getJSONObject("header"));
        toSign.put("payload", structure.getJSONObject("payload"));
        String signature = SignatureOperations.sign(privateKey, toSign.toString());

        trailer.put("signature", signature);
    }

    public static JSONObject prepareResponseJSONStructureSigned(InternalTopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message) throws Exception {
        JSONObject structure =  prepareResponseJSONStructure(topic.toString(), payload, status, message, "");
        // structure.getJSONObject("header").put("sign_alg", "sha256WithRSAEncryption");
        // signJSONStructure(structure);
        return structure;
    }

    public static JSONObject prepareResponseJSONStructureSigned(TopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message) throws Exception {
        JSONObject structure =  prepareResponseJSONStructure(topic.toString(), payload, status, message, "");
        // structure.getJSONObject("header").put("sign_alg", "sha256WithRSAEncryption");
        // signJSONStructure(structure);
        return structure;
    }

    public static JSONObject prepareResponseJSONStructureSigned(InternalTopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message, String cor_id) throws Exception {
        JSONObject structure =  prepareResponseJSONStructure(topic.toString(), payload, status, message, cor_id);
        // structure.getJSONObject("header").put("sign_alg", "sha256WithRSAEncryption");
        // signJSONStructure(structure);
        return structure;
    }

    public static JSONObject prepareResponseJSONStructureSigned(TopicName topic, JSONObject payload, ResultJSONStructureStatus status, String message, String cor_id) throws Exception {
        JSONObject structure =  prepareResponseJSONStructure(topic.toString(), payload, status, message, cor_id);
        // structure.getJSONObject("header").put("sign_alg", "sha256WithRSAEncryption");
        // signJSONStructure(structure);
        return structure;
    }

    // -----------------------------------------------------------------------------------------------------------------

    public enum ResultJSONStructureStatus {
        OK, ERROR
    }

    public enum TopicName {
        DEVICE_VULNERABILITY(12, "Device.Vulnerability"),
        DEVICE_PROFILE_UPDATE(13, "Device.Profile.Update"),
        DEVICE_COMPROMISED(17, "Device.Compromised"),
        DEVICE_PATCH_UPDATED(18, "Device.Patch.Updated"),
        DEVICE_PATCH_AVAILABLE(19, "Device.Patch.Available"),
        DEVICE_RISK(20, "Device.Risk"),
        DEVICE_BELIEF(21, "Device.Belief"),
        DEVICE_ALERT(22, "Device.Alert"),
        DEVICE_TRUST_UPDATE(23, "Device.Trust.Update"),
        DEVICE_HEALTH_STATUS(24, "Device.Health.Status"),
        DEVICE_IMPORTANCE(25, "Device.Importance"),
        DEVICE_REGISTER(26, "Device.Register"),
        DEVICE_UNREGISTER(27, "Device.Unregister"),
        NETWORK_TOPOLOGY(28, "Network.Topology"),
        NETWORK_ATTACK(29, "Network.Attack"),
        RESPONSE_MITIGATION(30, "Response.Mitigation"),
        RESPONSE_DECISION(31, "Response.Decision"),
        NETWORK_RISK(0, "Network.Risk"),
        APPLICABLE_MITIGATIONS(0, "Applicable.Mitigations"),
        SOHO_CONFIG(0, "SOHO.Config");

        private final String topic;
        private final int id;
        private TopicName(int id, String topic) {
            this.topic = topic;
            this.id = id;
        }

        @Override
        public String toString() {
            String prefix = ProjectProperties.getProperty("bus-topic-prefix");
            return prefix + this.topic;
        }
        public int getId() { return this.id; }
        public String getTopic() { return this.toString(); }
    }

    public enum InternalTopicName {
        TEST(0, "Internal.iRG.Test");

        private final String topic;
        private final int id;
        private InternalTopicName(int id, String topic) {
            this.id = id;
            this.topic = topic;
        }

        @Override
        public String toString() {
            String prefix = ProjectProperties.getProperty("bus-topic-prefix");
            return prefix + this.topic;
        }
        public int getId() { return this.id; }
        public String getTopic() { return this.toString(); }
    }

    public static void print_message(Level level, String message) {
        String msg = "[*] " + message;
        Logger.getAnonymousLogger().log(level, msg);
    }
}































































/*
    You're the cause of my pain,
    but what can I do; what can I do?

    We're both married together,
    please return back to me.
    For you I'll jump off a cliff,
    come on, come on, please come back to me.

    Don't put a fire, in my heart;
    don't put a fire, in my poor, poor heart.
    For you I'll jump off a cliff,
    come on, come on, please come back to me.

    We're both married together,
    please return back to me...

    (discogs.com/master/1356090)
*/
