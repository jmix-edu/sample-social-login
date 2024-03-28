package com.company.sociallogin.security;

import com.company.sociallogin.entity.User;
import io.jmix.security.role.RoleGrantedAuthorityUtils;
import io.jmix.securityflowui.FlowuiSecurityConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

@EnableWebSecurity
@Configuration
public class OAuth2SecurityConfiguration extends FlowuiSecurityConfiguration {

    private static final Logger log = LoggerFactory.getLogger(OAuth2SecurityConfiguration.class);

    private final RoleGrantedAuthorityUtils authorityUtils;
    private final OAuth2UserPersistence oidcUserPersistence;

    public OAuth2SecurityConfiguration(RoleGrantedAuthorityUtils authorityUtils,
                                       OAuth2UserPersistence oidcUserPersistence) {
        this.authorityUtils = authorityUtils;
        this.oidcUserPersistence = oidcUserPersistence;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);

        http.oauth2Login(configurer ->
                configurer
                        .loginPage(getLoginPath())
                        .userInfoEndpoint(userInfoEndpointConfig ->
                                userInfoEndpointConfig
                                        .userService(oauth2UserService())
                                        .oidcUserService(oidcUserService()))
                        .successHandler(this::onAuthenticationSuccess)
        );
    }

    private void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException {
        // redirect to the main screen after successful authentication using auth provider
        new DefaultRedirectStrategy().sendRedirect(request, response, "/");
    }

    /**
     * Service responsible for loading OAuth2 users
     */
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OAuth2User oAuth2User = delegate.loadUser(userRequest);

            // todo implement

            return oAuth2User;
        };
    }

    /**
     * Service responsible for loading OIDC users (Google uses OIDC protocol)
     */
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);

            // todo implement

            return oidcUser;
        };
    }

    /**
     * Builds granted authority list that grants access to the FullAccess role
     */
    private Collection<GrantedAuthority> getDefaultGrantedAuthorities() {
        return List.of(authorityUtils.createResourceRoleGrantedAuthority(FullAccessRole.CODE));
    }
}
