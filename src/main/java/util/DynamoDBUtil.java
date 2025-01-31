package util;

import model.User;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import java.util.HashMap;
import java.util.Map;

public class DynamoDBUtil {
    private static final String TABLE_NAME = System.getenv("USER_TABLE");
    private static final DynamoDbClient dynamoDb = DynamoDbClient.builder().build();

    public static void saveUser(User user, String hashedPassword) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("email", AttributeValue.builder().s(user.getEmail()).build());
        item.put("password", AttributeValue.builder().s(hashedPassword).build());
        item.put("name", AttributeValue.builder().s(user.getName()).build());

        PutItemRequest request = PutItemRequest.builder()
                .tableName(TABLE_NAME)
                .item(item)
                .build();

        dynamoDb.putItem(request);
    }

    public static Map<String, AttributeValue> getUser(String email) {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("email", AttributeValue.builder().s(email).build());

        GetItemRequest request = GetItemRequest.builder()
                .tableName(TABLE_NAME)
                .key(key)
                .build();

        GetItemResponse response = dynamoDb.getItem(request);
        return response.item();
    }

    public static void updateUserProfileImage(String email, String imageUrl) {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put("email", AttributeValue.builder().s(email).build());

        Map<String, AttributeValueUpdate> updates = new HashMap<>();
        updates.put("profileImageUrl", AttributeValueUpdate.builder()
                .value(AttributeValue.builder().s(imageUrl).build())
                .action(AttributeAction.PUT)
                .build());

        UpdateItemRequest request = UpdateItemRequest.builder()
                .tableName(TABLE_NAME)
                .key(key)
                .attributeUpdates(updates)
                .build();

        dynamoDb.updateItem(request);
    }
}