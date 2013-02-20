import logging

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy

from zope.interface import implementer

log = logging.getLogger(__name__)

__all__ = ['get_authentication_policy']


def includeme(config):
    log.info('Configuring.')
    config.set_authentication_policy(ContextBasedAuthenticationPolicy())
    # XXX Permit to override authorization policy via settings?
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.commit()


def get_authentication_policy(config):
    return config.registry.getUtility(IAuthenticationPolicy)


class IContextBasedAuthenticationPolicy(IAuthenticationPolicy):

    def register_context(
        self,
        context,
        auth_policy
        ):
        ""


@implementer(IContextBasedAuthenticationPolicy)
class ContextBasedAuthenticationPolicy(CallbackAuthenticationPolicy):

    def __init__(self):
        self._context_policies = {}

    def register_context(
        self,
        context_class,
        auth_policy,
        ):
        log.debug('registering %s.', context_class)

        self._context_policies[context_class] = auth_policy

    def _call_method(self, request, method_name, *args, **kwargs):
        try:
            policy = self._context_policies[request.context.__class__]
            method = getattr(policy, method_name)
        except (KeyError, AttributeError):
            return None
        return method(request, *args, **kwargs)

    def authenticated_userid(self, request):
        """ Return the authenticated userid or ``None`` if no authenticated
        userid can be found. This method of the policy should ensure that a
        record exists in whatever persistent store is used related to the
        user (the user should not have been deleted); if a record associated
        with the current id does not exist in a persistent store, it should
        return ``None``."""
        try:
            policy = self._context_policies[request.context.__class__]
            return policy.authenticated_userid(request)
        except (KeyError, AttributeError):
            parent = super(ContextBasedAuthenticationPolicy, self)
            return parent.authenticated_userid(request)

    def unauthenticated_userid(self, request):
        """ Return the *unauthenticated* userid.  This method performs the
        same duty as ``authenticated_userid`` but is permitted to return the
        userid based only on data present in the request; it needn't (and
        shouldn't) check any persistent store to ensure that the user record
        related to the request userid exists."""
        return self._call_method(request, 'unauthenticated_userid')

    def effective_principals(self, request):
        """ Return a sequence representing the effective principals
        including the userid and any groups belonged to by the current
        user, including 'system' groups such as Everyone and
        Authenticated. """
        cls = ContextBasedAuthenticationPolicy
        principals = super(cls, self).effective_principals(request)
        extended = self._call_method(request, 'effective_principals')
        if extended:
            principals.extend(extended)
        return principals

    def remember(self, request, principal, **kw):
        """ Return a set of headers suitable for 'remembering' the
        principal named ``principal`` when set in a response.  An
        individual authentication policy and its consumers can decide
        on the composition and meaning of ``**kw.`` """
        headers = self._call_method(request, 'remember', principal, **kw)
        return headers if headers else []

    def forget(self, request):
        """ Return a set of headers suitable for 'forgetting' the
        current user on subsequent requests. """
        headers = self._call_method(request, 'forget')
        return headers if headers else []
