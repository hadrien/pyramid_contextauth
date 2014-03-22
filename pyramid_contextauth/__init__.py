import logging
import collections

import venusian

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy

from zope.interface import implementer

log = logging.getLogger(__name__)

__all__ = ['get_authentication_policy']


def includeme(config):
    log.info('Configuring.')
    policy = config.registry.queryUtility(IContextBasedAuthenticationPolicy)
    if policy is None:
        ctx_policy = ContextBasedAuthenticationPolicy()
        config.set_authentication_policy(ctx_policy)
        # XXX Permit to override authorization policy via settings?
        config.set_authorization_policy(ACLAuthorizationPolicy())
        config.add_directive('register_authentication_policy',
                             register_auth_policy,
                             action_wrap=True)
        config.commit()


class authentication_policy(object):
    """A decorator to register an authentication policy"""

    def __init__(self, *context_cls_list):
        self.context_cls_list = context_cls_list

    def __call__(self, policy_cls):
        self.policy_cls = policy_cls
        self.info = venusian.attach(policy_cls, self.callback)
        return policy_cls

    def callback(self, context, name, ob):
        config = context.config.with_package(self.info.module)
        config.register_authentication_policy(self.policy_cls(),
                                              self.context_cls_list)


def register_auth_policy(config, policy, context_cls_list):
    ctx_policy = config.registry.getUtility(IAuthenticationPolicy)
    ctx_policy.register_context(config, context_cls_list, policy)


def get_authentication_policy(config):
    return config.registry.getUtility(IAuthenticationPolicy)


class IContextBasedAuthenticationPolicy(IAuthenticationPolicy):

    def register_context(self, context, auth_policy):
        ""


@implementer(IContextBasedAuthenticationPolicy)
class ContextBasedAuthenticationPolicy(CallbackAuthenticationPolicy):

    def register_context(self, config, context_cls_list, auth_policy):
        log.debug('registering auth_policy=%s for %s', auth_policy,
                  context_cls_list)
        registry = config.registry
        if not isinstance(context_cls_list, collections.Iterable):
            context_cls_list = (context_cls_list, )

        def factory(context):
            return auth_policy

        for ctx in context_cls_list:
            registry.registerAdapter(factory, required=[ctx],
                                     provided=IAuthenticationPolicy)

    def _get_policy(self, request):
        registry = request.registry
        return registry.queryAdapter(request.context, IAuthenticationPolicy)

    def _call_method(self, request, method_name, *args, **kwargs):
        policy = self._get_policy(request)
        if not policy:
            return None
        try:
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
        policy = self._get_policy(request)
        try:
            return policy.authenticated_userid(request)
        except AttributeError:
            log.debug('No policy for context=%s', request.context)
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
