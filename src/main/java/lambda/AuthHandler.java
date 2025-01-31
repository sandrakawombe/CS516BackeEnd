package lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import model.LoginRequest;
import model.SignupRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.core.sync.RequestBody;
import com.google.gson.Gson;
import org.mindrot.jbcrypt.BCrypt;
import software.amazon.awssdk.regions.Region;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Base64;

public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final String MY_AWS_REGION = System.getenv("MY_AWS_REGION");

    private final DynamoDbClient dynamoDb = DynamoDbClient.builder()
            .region(Region.of(MY_AWS_REGION))  // Set DynamoDB region to us-east-1
            .build();

    private final S3Client s3Client = S3Client.builder()
            .region(Region.of(MY_AWS_REGION))  // Set S3 region to us-east-1
            .build();

    private final String USER_TABLE = System.getenv("USER_TABLE");
    private final String S3_BUCKET = System.getenv("S3_BUCKET");
    private final String JWT_SECRET = System.getenv("JWT_SECRET");
    private final Gson gson = new Gson();
    Map<String, String> responseBody = new HashMap<>();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        String path = input.getPath();
        String method = input.getHttpMethod();

        if ("/auth/signup".equals(path) && "POST".equals(method)) {
            return handleSignup(input);
        } else if ("/auth/login".equals(path) && "POST".equals(method)) {
            return handleLogin(input);
        } else if ("/auth/upload-image".equals(path) && "POST".equals(method)) {
            return handleImageUpload(input);
        }

        return createResponse(400, "Invalid endpoint");
    }

    private APIGatewayProxyResponseEvent handleSignup(APIGatewayProxyRequestEvent input) {
        try {
            SignupRequest request = gson.fromJson(input.getBody(), SignupRequest.class);

            // Hash password
            String hashedPassword = BCrypt.hashpw(request.getPassword(), BCrypt.gensalt());

            // Store user in DynamoDB
            Map<String, AttributeValue> item = new HashMap<>();
            item.put("email", AttributeValue.builder().s(request.getEmail()).build());
            item.put("password", AttributeValue.builder().s(hashedPassword).build());
            item.put("name", AttributeValue.builder().s(request.getName()).build());

            PutItemRequest putItemRequest = PutItemRequest.builder()
                    .tableName(USER_TABLE)
                    .item(item)
                    .build();

            dynamoDb.putItem(putItemRequest);
            responseBody.put("responseCode", "200");
            responseBody.put("responseDesc", "User created successfully");
            return createResponse(200, gson.toJson(responseBody));
        } catch (Exception e) {
            responseBody.put("responseCode", "500");
            responseBody.put("responseDesc", "Error creating user: " + e.getMessage());
            return createResponse(500, gson.toJson(responseBody));
        }
    }

    private APIGatewayProxyResponseEvent handleLogin(APIGatewayProxyRequestEvent input) {
        try {
            LoginRequest request = gson.fromJson(input.getBody(), LoginRequest.class);

            // Get user from DynamoDB
            Map<String, AttributeValue> key = new HashMap<>();
            String emailToQuery = request.getEmail().trim();
            key.put("email", AttributeValue.builder().s(emailToQuery).build());
            System.out.println("Querying for email: '" + emailToQuery+"'");
            System.out.println("Querying from table: " + USER_TABLE);
            System.out.println("DynamoDB query key: " + key);


            GetItemRequest getItemRequest = GetItemRequest.builder()
                    .tableName(USER_TABLE)
                    .key(key)
                    .build();

            GetItemResponse response = dynamoDb.getItem(getItemRequest);
            System.out.println("DynamoDB query response: " + response);

            if (response.hasItem()) {
                System.out.println("Item found in DynamoDB");
                String storedHash = response.item().get("password").s();
                if (BCrypt.checkpw(request.getPassword(), storedHash)) {
                    String token = JWT.create()
                            .withSubject(request.getEmail())
                            .sign(Algorithm.HMAC256(JWT_SECRET));

                    responseBody.put("responseCode", "200");
                    responseBody.put("responseDesc", "Success");
                    responseBody.put("token", token);
                    return createResponse(200, gson.toJson(responseBody));
                } else {
                    System.out.println("Password mismatch");
                    responseBody.put("responseCode", "404");
                    responseBody.put("responseDesc", "Password mismatch");
                    return createResponse(404, gson.toJson(responseBody));
                }
            } else {
                System.out.println("Invalid credentials");
                responseBody.put("responseCode", "401");
                responseBody.put("responseDesc", "Invalid credentials");
                return createResponse(401, gson.toJson(responseBody));
            }

        } catch (Exception e) {
            System.out.println("Error during login: " + e.getMessage());
            responseBody.put("responseCode", "500");
            responseBody.put("responseDesc", "Error during login: " + e.getMessage());
            return createResponse(500, gson.toJson(responseBody));
        }
    }

    private APIGatewayProxyResponseEvent handleImageUpload(APIGatewayProxyRequestEvent input) {
        try {
            // Verify JWT token
            String token = input.getHeaders().get("Authorization").replace("Bearer ", "");
            String email = JWT.require(Algorithm.HMAC256(JWT_SECRET))
                    .build()
                    .verify(token)
                    .getSubject();

            // Process image upload
            String image = input.getBody(); // Base64 encoded image
            // Remove the data URI scheme (e.g., data:image/jpeg;base64,)
           // String imageData = image.replaceAll("^data:image\\/[^;]+;base64,", "");

            byte[] decodedImage = Base64.getDecoder().decode(image);
            String key = "profiles/" + UUID.randomUUID().toString() + ".jpg";

            // Upload to S3
            s3Client.putObject(PutObjectRequest.builder()
                            .bucket(S3_BUCKET)
                            .key(key)
                            .build(),
                    RequestBody.fromBytes(decodedImage));

            // Update user profile in DynamoDB
            Map<String, AttributeValue> keyMap = new HashMap<>();
            keyMap.put("email", AttributeValue.builder().s(email).build());

            // Correctly use AttributeValueUpdate for DynamoDB
            Map<String, AttributeValueUpdate> updates = new HashMap<>();

            // Create AttributeValueUpdate for 'profileImage'
            AttributeValueUpdate update = AttributeValueUpdate.builder()
                    .value(AttributeValue.builder().s(key).build())  // Setting the new profileImage value
                    .action(AttributeAction.PUT)  // Using the PUT action to overwrite the value
                    .build();

            updates.put("profileImage", update);

            // Create the UpdateItemRequest
            UpdateItemRequest updateRequest = UpdateItemRequest.builder()
                    .tableName(USER_TABLE)
                    .key(keyMap)
                    .attributeUpdates(updates)  // Use the Map<String, AttributeValueUpdate> here
                    .build();

            // Execute the update
            dynamoDb.updateItem(updateRequest);

            return createResponse(200, "Image uploaded successfully");
        } catch (Exception e) {
            return createResponse(500, "Error uploading image: " + e.getMessage());
        }
    }

    private APIGatewayProxyResponseEvent createResponse(int statusCode, String body) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setStatusCode(statusCode);
        response.setBody(body);

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Access-Control-Allow-Origin", "*");
        response.setHeaders(headers);

        return response;
    }
}
