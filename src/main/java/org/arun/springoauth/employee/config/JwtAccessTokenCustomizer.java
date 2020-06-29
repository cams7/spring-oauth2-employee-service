package org.arun.springoauth.employee.config;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.JwtAccessTokenConverterConfigurer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAccessTokenCustomizer extends DefaultAccessTokenConverter implements
    JwtAccessTokenConverterConfigurer {

  private static final Logger LOG = LoggerFactory.getLogger(JwtAccessTokenCustomizer.class);

  private static final String CLIENT_NAME_ELEMENT_IN_JWT = "aud";

  private static final String ROLE_ELEMENT_IN_JWT = "authorities";

  private ObjectMapper mapper;

  @Autowired
  public JwtAccessTokenCustomizer(ObjectMapper mapper) {
    this.mapper = mapper;
    LOG.info("Initialized {}", JwtAccessTokenCustomizer.class.getSimpleName());
  }

  @Override
  public void configure(JwtAccessTokenConverter converter) {
    converter.setAccessTokenConverter(this);
    LOG.info("Configured {}", JwtAccessTokenConverter.class.getSimpleName());
  }

  /**
   * Spring oauth2 expects roles under authorities element in tokenMap, but keycloak provides it under
   * resource_access. Hence extractAuthentication method is overriden to extract roles from resource_access.
   *
   * @return OAuth2Authentication with authorities for given application
   */
  @Override
  public OAuth2Authentication extractAuthentication(Map<String, ?> tokenMap) {
    JsonNode token = mapper.convertValue(tokenMap, JsonNode.class);
    Set<String> audienceList = extractClients(token); // extracting client names
    List<GrantedAuthority> authorities = extractRoles(token); // extracting client roles

    OAuth2Authentication authentication = super.extractAuthentication(tokenMap);
    OAuth2Request oAuth2Request = authentication.getOAuth2Request();

    OAuth2Request request = new OAuth2Request(oAuth2Request.getRequestParameters(), oAuth2Request.getClientId(),
        authorities, true, oAuth2Request.getScope(), audienceList, null, null, null);

    Authentication usernamePasswordAuthentication = new UsernamePasswordAuthenticationToken(authentication
        .getPrincipal(), "N/A", authorities);
    return new OAuth2Authentication(request, usernamePasswordAuthentication);
  }

  private static List<GrantedAuthority> extractRoles(JsonNode jwt) {
    if (!jwt.has(ROLE_ELEMENT_IN_JWT))
      throw new IllegalArgumentException(String.format("Expected element %s not found in token",
          ROLE_ELEMENT_IN_JWT));

    Set<String> rolesWithPrefix = new HashSet<>();
    jwt.path(ROLE_ELEMENT_IN_JWT).elements().forEachRemaining(autority -> rolesWithPrefix.add(autority.asText()));

    final List<GrantedAuthority> authorityList = AuthorityUtils.createAuthorityList(rolesWithPrefix.toArray(
        new String[0]));
    return authorityList;
  }

  private static Set<String> extractClients(JsonNode jwt) {
    if (!jwt.has(CLIENT_NAME_ELEMENT_IN_JWT))
      throw new IllegalArgumentException(String.format("Expected element %s not found in token",
          CLIENT_NAME_ELEMENT_IN_JWT));

    final Set<String> clientNames = new HashSet<>();
    jwt.path(CLIENT_NAME_ELEMENT_IN_JWT).forEach(node -> clientNames.add(node.asText()));
    return clientNames;
  }

}
