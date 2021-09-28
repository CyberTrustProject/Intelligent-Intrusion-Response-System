package org.fiware.cybercaptor.server.system;

import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.properties.ProjectProperties;
import org.fiware.cybercaptor.server.rest.RestApplication;
import org.fiware.cybercaptor.server.rest.RestJsonAPIv2;
import org.json.JSONObject;

import java.io.*;
import java.util.Date;
import java.util.logging.Logger;

public class LoggingHelperFunctions {

    // Used to time code segments.
    public static class LogEvent {
        static final String filename = "events.csv";
        static final String headers = "timestamp,point,event";
        static final String delimiter = ",";

        public static void start(String event) {
            record(event, "START");
        }

        public static void stop(String event) {
            record(event, "STOP");
        }

        // Do not use with short events. Use the normal record() instead.
        public static void recordThreaded(final String event, final String point) {
            Thread recordEventToFile = new Thread(
                    new Runnable() {
                        @Override
                        public void run() {
                            record(event, point);
                        }
                    }
            );
            recordEventToFile.start();
        }

        public static void record(String event, String point) {
            String line = getCurrentTimeString() + delimiter + point + delimiter + event;

            String path = ProjectProperties.getProperty("logs-path");
            path += filename;

            PrintWriter pw = null;
            try {
                File file = new File(path);
                if (!file.exists()) {
                    file.createNewFile();
                }

                pw = new PrintWriter(new BufferedWriter(new FileWriter(path, true)));
                pw.println(line);

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (pw != null) {
                    pw.close();
                }
            }
        }
    }

    public static void saveGraphToFile(String filename, AttackGraph graph, String message) {
        JSONObject payload = new JSONObject();
        payload.put("attack_graph", RestJsonAPIv2.mulval_attack_graph(graph.toDomElement(), graph));
        JSONObject response = RestApplication.prepareResponseJSONStructure(
                RestApplication.InternalTopicName.TEST,
                payload,
                RestApplication.ResultJSONStructureStatus.OK,
                message
        );

        logToFile(filename, response.toString());
    }

    // Will remove any existing files with the same name.
    public static void logToFile(String filename, String contents) {
        String path = ProjectProperties.getProperty("logs-path");
        // path += getCurrentTimeString() + "-" + filename;
        path += filename;

        if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
            Logger.getAnonymousLogger().info("Writing to: " + path);
        }

        PrintWriter file = null;
        try {
            file = new PrintWriter(path);
            file.print(contents);
            file.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void logToFileThreaded(final String filename, final String contents) {
        final Thread logToFile = new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        logToFile(filename, contents);
                    }
                }
        );
        logToFile.start();
    }

    // In milliseconds.
    public static String getCurrentTimeString() {
        return Long.toString(new Date().getTime());
    }

    public static Long getCurrentTime() {
        return new Date().getTime();
    }
}
