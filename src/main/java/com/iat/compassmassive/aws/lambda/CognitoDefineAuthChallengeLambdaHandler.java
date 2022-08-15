package com.iat.compassmassive.aws.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;

public class CognitoDefineAuthChallengeLambdaHandler implements RequestStreamHandler {
    public ObjectMapper mapper = new ObjectMapper();

    @Override
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
        LambdaLogger log = context.getLogger();
        log.log("InputStream:" + inputStream);
        JsonNode mainNode = mapper.readTree(inputStream);
        JsonNode requestNode = mainNode.get("request");

        JsonNode responseNode = mainNode.get("response");
        if (Boolean.parseBoolean(requestNode.get("userNotFound").asText())) {

            ((ObjectNode) responseNode).put("issueToken", false);
            ((ObjectNode) responseNode).put("failAuthentication", true);
            throw new IllegalArgumentException("User does not exist in the cognito pool");

        }

        JsonNode session = requestNode.get("session");
        int sessionLength = mapper.convertValue(session, ArrayList.class).size();
        if ((sessionLength) >= 3 && !Boolean.parseBoolean(session.get(sessionLength - 1).get("challengeRequest").asText())) {
            ((ObjectNode) responseNode).put("issueTokens", false);
            ((ObjectNode) responseNode).put("failAuthentication", true);
            throw new IllegalArgumentException("Invalid OTP even after completing 3 times");
        } else if ((sessionLength) > 0 && !Boolean.parseBoolean(session.get(sessionLength - 1).get("challengeRequest").asText())) {
            ((ObjectNode) responseNode).put("issueTokens", true);
            ((ObjectNode) responseNode).put("failAuthentication", false);
        } else {
            ((ObjectNode) responseNode).put("issueTokens", false);
            ((ObjectNode) responseNode).put("failAuthentication", false);
            ((ObjectNode) responseNode).put("challengeName", "CUSTOM_CHALLENGE");
        }
        mapper.writeValue(outputStream, mainNode);
    }

}