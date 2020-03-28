package com.baeldung.newstack.spring;

import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author miguel, 28/3/20
 * @project new-stack
 */
public class CustomAuthorityExtractor implements AuthoritiesExtractor {

    private final static String BAELDUNG_DOMAIN = "baeldung.com";
    private final static String USER_NAME_CLAIM = "preferred_username";
    private final static String AUTHORITY = "authority";

    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(getAuthoritiesAsString(map));
    }

    private String getAuthoritiesAsString(Map<String, Object> map) {
        String username = (String) map.get(USER_NAME_CLAIM);
        // Authorities
        List<String> authorities = new ArrayList<>();
        List<LinkedHashMap<String, String>> jwtAuthorities = (List<LinkedHashMap<String, String>>) map.get("authorities");
        for (LinkedHashMap<String, String> entry : jwtAuthorities) {
            authorities.add(entry.get(AUTHORITY));
        }
        // Add new authority if necessary
        if(EmailValidator.getInstance().isValid(username) && username.substring(username .indexOf("@") + 1).equals(BAELDUNG_DOMAIN)){
            authorities.add("SUPERUSER");
        }
        return String.join(",", authorities);
    }
}
