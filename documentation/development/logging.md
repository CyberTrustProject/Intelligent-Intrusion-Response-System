# iRG Server logging notes

### Logging levels
* `INFO` ⟶ Anything returning HTTP 200. When the call was successful.
* `WARNING` ⟶ Anything returning HTTP 4XX. When the system encountered an error from which it recovered.
* `SEVERE` ⟶ Anything returning HTTP 500. When the system encountered a fatal error.

### Message unique strings

Each log message starts with one of the following strings (to make log parsing easier).
* `[API CALL] [START]` \& `[API CALL] [FINISHED]` at the start and end of each API call.
* `[INPUT]` \& `[OUTPUT]` for log messages reporting API call inputs or iRG Server response.
    * `[JSON]` \& `[XML]` after the previous string to specify the format.

### TODO
* The whole v1 API
* Save all attack graphs (MulVAL, Original and their reduced versions) to JSON files.
    * Each graph will be stored in a separate directory `/timestamp-attack-graph/`
    * Four graphs will be stored inside this directory: `MulVAL.json`, `Original.json`, `MulVAL-Reduced.json`, `Original-Reduced.json`

### Code snippets

Standard messages displayed by every call:
```java
Logger.getAnonymousLogger().info("[API CALL] [START] " + request.getMethod() + ":/v2/NAME, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
Logger.getAnonymousLogger().info("[API CALL] [FINISHED] " + request.getMethod() + ":/v2/NAME, Source: " + request.getRemoteAddr() + ", Timestamp: " + LoggingHelperFunctions.getCurrentTimeString());
```

For the input/output needs of each call:
```java
// At the beginning of each call.
// Replace [JSON] with [XML] or whatever is most appropriate.
if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
    Logger.getAnonymousLogger().info("[INPUT] [JSON] Received: " + );
}

// At the RestApplication.returnJsonObject object.
if (ProjectProperties.getProperty("debug-flag").equalsIgnoreCase("true")) {
    Logger.getAnonymousLogger().info("Responded with: HTTP " + status.getStatusCode() + " " + status.getReasonPhrase());
    Logger.getAnonymousLogger().info("[OUTPUT] [JSON] Response: " + jsonObject);
}
```

Other messages:
```java
// When the `Monitoring` object was not found:
Logger.getAnonymousLogger().severe("The monitoring object is empty, the system was not initialized");

// For any errors during JSON parsing:
Logger.getAnonymousLogger().severe("Error during input JSON parsing");

// For any errors when generating the CSV files:
Logger.getAnonymousLogger().severe("Error while exporting to CSV");

// When something must be recorded in a separate file:
LoggingHelperFunctions.logToFile("filename.ext", string);

// For unknown exceptions:
Logger.getAnonymousLogger().warning("Unknown exception");

// For information bus errors:
Logger.getAnonymousLogger().warning("Error when contacting the information bus");
```
