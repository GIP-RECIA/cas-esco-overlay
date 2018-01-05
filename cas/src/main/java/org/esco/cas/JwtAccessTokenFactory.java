package org.esco.cas;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.AccessToken;
import org.apereo.cas.ticket.accesstoken.AccessTokenFactory;
import org.apereo.cas.ticket.accesstoken.AccessTokenImpl;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * OAuth JWT Access Token factory.
 */
public class JwtAccessTokenFactory extends JwtBaseTokenFactory implements AccessTokenFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAccessTokenFactory.class);

    public JwtAccessTokenFactory(ExpirationPolicy expirationPolicy) {
        super(expirationPolicy);
    }

    @Override
    public <T extends TicketFactory> T get(final Class<? extends Ticket> clazz) {
        return (T) this;
    }

    @Override
    public AccessToken create(Service service, Authentication authentication, TicketGrantingTicket ticketGrantingTicket, Collection<String> scopes) {
        LOGGER.debug("Generating JWT Access Token");

        LOGGER.debug("Attempting to produce claims for the access token of principal [{}]", authentication.getPrincipal().getId());
        OidcRegisteredService registeredService = (OidcRegisteredService)servicesManager.findServiceBy(service);
        final JwtClaims claims = produceIdTokenClaims(authentication, expirationPolicy.getTimeToLive(), registeredService);
        LOGGER.debug("Produce claims for the access token of principal [{}] as [{}]", authentication.getPrincipal().getId(), claims);

        String codeId = this.signingService.encode(registeredService, claims);

        AccessToken at = new AccessTokenImpl(codeId, service, authentication, this.expirationPolicy, ticketGrantingTicket, scopes);
        if (ticketGrantingTicket != null) {
            ticketGrantingTicket.getDescendantTickets().add(at.getId());
        }

        return at;
    }
}
