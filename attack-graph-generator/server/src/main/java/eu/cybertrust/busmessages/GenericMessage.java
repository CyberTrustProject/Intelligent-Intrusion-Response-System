package eu.cybertrust.busmessages;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import eu.cybertrust.cryptoutils.ConfigManagement;
import eu.cybertrust.cryptoutils.SignatureOperations;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;

@JsonFilter("signatureFilter")
public class GenericMessage {

	private Map<String, String> header = new HashMap<String, String>();
	private Map<String, Object> payload = new HashMap<String, Object>();
	private Map<String, String> trailer = new HashMap<String, String>();
	@JsonIgnore
	private String jsonString = null;

	public GenericMessage() {
		header.put("msg_id", UUID.randomUUID().toString());
	}

	public static GenericMessage createMessageFromJSON(String json) throws JsonMappingException, JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();
		GenericMessage gm = objectMapper.readValue(json, GenericMessage.class);
		gm.jsonString = json;
		return gm;
	}

	/**
	 * @return the source
	 */
	@JsonIgnore
	public String getSource() {
		return header.get("source");
	}
	/**
	 * @param source the source to set
	 */
	public GenericMessage setSource(String source) {
		header.put("source", source);
		return this;
	}
	/**
	 * @return the message topic
	 */
	@JsonIgnore
	public String getMsgTopic() {
		return header.get("msg_topic");
	}
	/**
	 * @param type the message topic to set
	 */
	public GenericMessage setMsgTopic(String topic) {
		header.put("msg_topic", topic);
		return this;
	}
	/**
	 * @return the message id
	 */
	@JsonIgnore
	public String getMsgId() {
		return header.get("msg_id");
	}
	/**
	 * @param msgId the message id to set
	 */
	public GenericMessage setMsgId(String msgId) {
		header.put("msg_id", msgId);
		return this;
	}
	/**
	 * @return the correlation id
	 */
	@JsonIgnore
	public String getCorId() {
		return header.get("cor_id");
	}
	/**
	 * @param corId the correlation id to set
	 */
	public GenericMessage setCorId(String corId) {
		header.put("cor_id", corId);
		return this;
	}
	/**
	 * @return the timestamp
	 */
	@JsonIgnore
	public long getTimestamp() {
		return Long.parseLong(header.get("timestamp"));
	}
	/**
	 * @param timestamp the timestamp to set
	 */
	@JsonIgnore
	public GenericMessage setTimestamp(long timestamp) {
		header.put("timestamp", Long.toString(timestamp));
		return this;
	}
	/**
	 * @return the payload
	 */
	public Map<String, Object> getPayload() {
		return payload;
	}
	/**
	 * @param payload the payload to set
	 */
	public GenericMessage setPayload(Map<String, Object> payload) {
		this.payload = payload;
		return this;
	}
	/**
	 * @return the signature
	 */
	@JsonIgnore
	public String getSignature() {
		return trailer.get("signature");
	}
	/**
	 * @throws UnsupportedEncodingException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public GenericMessage sign() throws IllegalArgumentException, JsonProcessingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException {
		header.put("sign_alg", ConfigManagement.getSignatureAlgorithm());
		this.trailer.clear();
		// get the message without the signature
		String stringToSign = this.toJSONNoSignature();
		String signatureString = SignatureOperations.sign(ConfigManagement.getMyPrivateKey(), stringToSign);
		trailer.put("signature", signatureString);
		// return the string representation: one signs a message to send it afterwards
		return this;
	}

	public boolean hasValidSignature() {
		String alg = header.get("sign_alg");
		String source = header.get("source");
		RSAPublicKey pubKey = ConfigManagement.getPublicKey(source);
		try {
			String jsonWithoutSignatureToCheck;
			if (jsonString != null) {
				// Message has been created via createMessageFromJSON; this will be the string representation that will be used
				jsonWithoutSignatureToCheck = jsonString.replaceFirst(",\"trailer\":\\{\"signature\":\"[^\"]+\"\\}\\}$", "}");
			}
			else {
				jsonWithoutSignatureToCheck = this.toJSONNoSignature();
			}
			return SignatureOperations.verify(pubKey, jsonWithoutSignatureToCheck, this.trailer.get("signature"), alg);
		}
		catch (Exception e) {
			return false;
		}
	}

	public void addPayloadField(String key, Object value) {
		payload.put(key, value);
	}

	public void removePayloadField(String key) {
		payload.remove(key);
	}

	public Object getPayloadKeyValue(String key) {
		return payload.get(key);
	}


	public String toJSON() throws JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();
		SimpleBeanPropertyFilter theFilter = SimpleBeanPropertyFilter.serializeAllExcept("jsonString");
		FilterProvider filters = new SimpleFilterProvider().addFilter("signatureFilter", theFilter);
		return objectMapper.writer(filters).writeValueAsString(this);
	}

	public String toJSONNoSignature() throws JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();
		Set<String> excludes = new HashSet<String>();
		excludes.add("_metadata");
		excludes.add("trailer");
		excludes.add("jsonString");
		SimpleBeanPropertyFilter theFilter = SimpleBeanPropertyFilter.serializeAllExcept(excludes);
		FilterProvider filters = new SimpleFilterProvider().addFilter("signatureFilter", theFilter);
		return objectMapper.writer(filters).writeValueAsString(this);
	}

	@JsonIgnore
	public String getSignedMessage() throws JsonProcessingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException {
		String stringToSign = toJSONNoSignature();
		String signatureString = SignatureOperations.sign(ConfigManagement.getMyPrivateKey(), stringToSign);
		// append the signature to the text obtained, properly enclosed
		String string2add = ",\"trailer\":{\"signature\":\"" + signatureString + "\"}}";
		String result = stringToSign.substring(0, stringToSign.length() - 1) + string2add;
		return result;
	}

	public Map<String, String> getHeader() {
		return header;
	}

	public GenericMessage setHeader(Map<String, String> h) {
		header = h;
		return this;
	}

	public Map<String, String> getTrailer() {
		return trailer;
	}

	public GenericMessage setTrailer(Map<String, String> t) {
		trailer= t;
		return this;
	}
}
