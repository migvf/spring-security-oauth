package com.baeldung.newstack.spring;

import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author miguel, 23/3/20
 * @project new-stack
 */
@Component
public class CustomClaimValidator implements OAuth2TokenValidator<Jwt> {

    private final static String BAELDUNG_DOMAIN = "baeldung.com";
    private final static String USER_NAME_CLAIM = "preferred_username";
    private List<OAuth2Error> errors;


    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        this.errors = new ArrayList<>();
        Map<String, Object> claims = jwt.getClaims();
        if(this.verifyClaims(claims)){
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(this.errors);
    }

    private boolean verifyClaims(Map<String, Object> claims){
        System.out.println(claims);
        final String username = (String) claims.get(USER_NAME_CLAIM);
        return isValidUserLength(username) && isValidUserDomain(username);
    }

    private boolean isValidUserLength(String username){
         if(StringUtils.isEmpty(username)){
             errors.add(new OAuth2Error("invalid_token", "User name length is not valid", null));
             return false;
         }
         return true;
    }

    private boolean isValidUserDomain(String username){
        if(!EmailValidator.getInstance().isValid(username)){
            errors.add(new OAuth2Error("invalid_token", "The user name it is not a valid email", null));
            return false;
        }else{
            String domain = username.substring(username .indexOf("@") + 1);
            if(!domain.equals(BAELDUNG_DOMAIN)){
                errors.add(new OAuth2Error("invalid_token", "The user name does not belong to the required domain", null));
                return false;
            }
            return true;
        }
    }
}
