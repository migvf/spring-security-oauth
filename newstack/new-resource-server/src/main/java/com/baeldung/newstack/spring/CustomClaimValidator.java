package com.baeldung.newstack.spring;

import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * @author miguel, 23/3/20
 * @project new-stack
 */
@Component
public class CustomClaimValidator {

    private final static String BAELDUNG_DOMAIN = "baeldung.com";
    private final static String USER_NAME_CLAIM = "preferred_username";

    public void verify(Map<String, Object> claims) throws InvalidTokenException {
        System.out.println(claims);
        final String username = (String) claims.get(USER_NAME_CLAIM);
        checkUserLength(username);
        checkUserDomain(username);
    }

    private void checkUserLength(String username){
        if ( StringUtils.isEmpty(username)) {
            throw new InvalidTokenException(USER_NAME_CLAIM.concat(" claim is empty"));
        }
    }

    private void checkUserDomain(String username){
        if(!EmailValidator.getInstance().isValid(username)){
            throw new InvalidTokenException(USER_NAME_CLAIM.concat(" claim is not a valid email"));
        }else{
            String domain = username.substring(username .indexOf("@") + 1);
            if(!domain.equals(BAELDUNG_DOMAIN)){
                throw new InvalidTokenException(USER_NAME_CLAIM.concat(" claim does not belong to baeldung domain"));
            }
        }
    }
}
