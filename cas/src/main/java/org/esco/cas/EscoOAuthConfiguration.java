package org.esco.cas;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.refreshtoken.OAuthRefreshTokenExpirationPolicy;
import org.apereo.cas.ticket.refreshtoken.RefreshTokenFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EscoOAuthConfiguration {
    private static final Logger LOGGER = LoggerFactory.getLogger(EscoOAuthConfiguration.class);

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    private ExpirationPolicy accessTokenExpirationPolicy;

    @Bean
    @RefreshScope
    public AccessTokenFactory defaultAccessTokenFactory() {
        LOGGER.debug("Creating JwtAccessTokenFactory");
        return new JwtAccessTokenFactory(accessTokenExpirationPolicy);
    }

    @Bean
    @RefreshScope
    public RefreshTokenFactory defaultRefreshTokenFactory() {
        LOGGER.debug("Creating JwtRefreshTokenFactory");
        return new JwtRefreshTokenFactory(refreshTokenExpirationPolicy());
    }

    private ExpirationPolicy refreshTokenExpirationPolicy() {
        return new OAuthRefreshTokenExpirationPolicy(casProperties.getAuthn().getOauth().getRefreshToken().getTimeToKillInSeconds());
    }
}
