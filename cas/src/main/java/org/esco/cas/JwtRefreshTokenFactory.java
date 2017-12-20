package org.esco.cas;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.token.OidcIdTokenSigningAndEncryptionService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.accesstoken.AccessTokenImpl;
import org.apereo.cas.ticket.refreshtoken.RefreshToken;
import org.apereo.cas.ticket.refreshtoken.RefreshTokenFactory;
import org.apereo.cas.ticket.refreshtoken.RefreshTokenImpl;
import org.apereo.cas.util.CollectionUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collection;
import java.util.UUID;
/**
 * JWT OAuth refresh token factory.
 */
public class JwtRefreshTokenFactory extends JwtBaseTokenFactory implements RefreshTokenFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRefreshTokenFactory.class);

    public JwtRefreshTokenFactory(ExpirationPolicy expirationPolicy) {
        super(expirationPolicy);
    }

    @Override
    public <T extends TicketFactory> T get(final Class<? extends Ticket> clazz) {
        return (T) this;
    }

    @Override
    public RefreshToken create(Service service, Authentication authentication, TicketGrantingTicket ticketGrantingTicket) {
        LOGGER.debug("Generating JWT Refresh Token");

        LOGGER.debug("Attempting to produce claims for the refresh token of principal [{}]", authentication.getPrincipal().getId());
        OidcRegisteredService registeredService = (OidcRegisteredService)servicesManager.findServiceBy(service);
        final JwtClaims claims = produceIdTokenClaims(authentication, expirationPolicy.getTimeToLive(), registeredService);
        LOGGER.debug("Produce claims for the refresh token of principal [{}] as [{}]", authentication.getPrincipal().getId(), claims);

        //TODO: Refresh token should maybe use another JSON Web Key than AccessToken.
        //TODO: We should add another signingService.
        String codeId = this.signingService.encode(registeredService, claims);

        RefreshToken rt = new RefreshTokenImpl(codeId, service, authentication, this.expirationPolicy, ticketGrantingTicket);
        if (ticketGrantingTicket != null) {
            ticketGrantingTicket.getDescendantTickets().add(rt.getId());
        }

        return rt;
    }
}
