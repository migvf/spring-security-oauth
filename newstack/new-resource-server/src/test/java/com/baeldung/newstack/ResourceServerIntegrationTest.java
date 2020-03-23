package com.baeldung.newstack;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * @author miguel, 23/3/20
 * @project new-stack
 */

/**
 * IMPORTANT To successfully run this test !!!
 * 1) we must to have launched new-auth-server before
 * 2) We must have created the users described in this test
 * 3) Our new-client must accept direct access grants
 * For points 2 and 3 we can use the keycloak ui to add/enable that(http://localhost:8083/auth) - admin user:bael-admin, password:pass
 */

@RunWith(SpringRunner.class)
@SpringBootTest(classes = NewResourceServerApp.class, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class ResourceServerIntegrationTest {

    private static final String URL_PREFIX = "http://localhost:8081/new-resource-server";
    private String incorrectUserTokenValue = null;
    private String validUserTokenValue = null;

    private static final String userNameWithInvalidDomain = "mig@test.com";
    private static final String passOfUserWithInvalidDomain = "test";

    private static final String userNameWithValidDomain = "mig@baeldung.com";
    private static final String passOfUserWithValidDomain = "mig";

    @Before
    public void obtainAccessToken() {
       String authCookieFromInvalidUser = this.getAuthCookie(userNameWithInvalidDomain, passOfUserWithInvalidDomain);
       final Response invalidUserResponse = this.getTokenResponse(authCookieFromInvalidUser, userNameWithInvalidDomain, passOfUserWithInvalidDomain);
       this.incorrectUserTokenValue = invalidUserResponse.jsonPath().getString("access_token");

        String authCookieFromValidUser = this.getAuthCookie(userNameWithValidDomain, passOfUserWithValidDomain);
        final Response validUserResponse = this.getTokenResponse(authCookieFromValidUser, userNameWithValidDomain, passOfUserWithValidDomain);
        this.validUserTokenValue = validUserResponse.jsonPath().getString("access_token");
    }

    @Test
    public void verifyAccessUsingInvalidUser(){
        Response response = RestAssured.given().header("Authorization", "Bearer " + this.incorrectUserTokenValue).get(URL_PREFIX + "/new-client/projects");
        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatusCode());
    }

    @Test
    public void verifyAccessUsingValidUser(){
        Response response = RestAssured.given().header("Authorization", "Bearer " + this.validUserTokenValue).get(URL_PREFIX + "/new-client/projects");
        assertEquals(HttpStatus.NOT_FOUND.value(), response.getStatusCode());
    }

    private String getAuthCookie(String userName, String userPass){
        final Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", "newClient");
        params.put("username", userName);
        params.put("password", userPass);
        params.put("response_type", "code");

        final Response response = RestAssured.given()
                .auth().preemptive().basic("newClient", "newClientSecret")
                .and().with().params(params)
                .when().post("http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/auth");
        return response.cookies().get("AUTH_SESSION_ID");
    }

    private Response getTokenResponse(String cookie, String userName, String userPass){
        final Map<String, String> params2 = new HashMap<>();
        params2.put("grant_type", "password");
        params2.put("client_id", "newClient");
        params2.put("username", userName);
        params2.put("password", userPass);

        return RestAssured.given()
                .cookie(cookie)
                .auth().preemptive().basic("newClient", "newClientSecret")
                .and().with().params(params2)
                .when().post("http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token");
    }
}
