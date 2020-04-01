package com.baeldung.newstack.spring;

import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;

/**
 * @author miguel, 31/3/20
 * @project new-stack
 */
public class CustomAuthorityConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    private final static String BAELDUNG_DOMAIN = "baeldung.com";
    private final static String USER_NAME_CLAIM = "preferred_username";

    @Override
    public Collection<GrantedAuthority> convert(final Jwt jwt) {
        //Extract authorities
        Collection<GrantedAuthority> jwtAuthorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
        Collection<GrantedAuthority> authorities = !CollectionUtils.isEmpty(jwtAuthorities) ? jwtAuthorities : new ArrayList<>();
        // Check if user belongs to baeldung domain
        if(this.checkIfUserNameBelongsToBaeldungDomain(jwt.getClaim(USER_NAME_CLAIM))){
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority("SUPERUSER");
            authorities.add(simpleGrantedAuthority);
        }
        return authorities;
    }

    private boolean checkIfUserNameBelongsToBaeldungDomain(String username){
        return EmailValidator.getInstance().isValid(username) && username.substring(username.indexOf("@") + 1).equals(BAELDUNG_DOMAIN);
    }


}