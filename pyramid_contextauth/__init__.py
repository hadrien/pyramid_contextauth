import logging
import collections

from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.location import lineage

from zope.interface import implementer, implementedBy

log = logging.getLogger(__name__)

__all__ = ['get_authentication_policy']


def includeme(config):
    try:
        config.get_authentication_policy()
    except AttributeError:
        log.info('Configuring')
        ctx_policy = ContextBasedAuthenticationPolicy()
        config.set_authentication_policy(ctx_policy)
        # TODO Permit to override authorization policy via settings.
        config.set_authorization_policy(ACLAuthorizationPolicy())
        config.add_directive('register_authentication_policy',
                             register_authentication_policy,
                             action_wrap=True)
        config.add_directive('get_authentication_policy',
                             get_authentication_policy,
                             action_wrap=False)
        config.commit()
        log.info('Configured')
    else:
        log.info('Already configured')


def register_authentication_policy(config, auth_policy, context_cls_list):
    intr_category = 'context based authentication policies'

    if any((
        isinstance(context_cls_list, (unicode, str)),
        not isinstance(context_cls_list, collections.Iterable),
    )):
        context_cls_list = (context_cls_list, )

    context_cls_list = [config.maybe_dotted(ctx) for ctx in context_cls_list]

    registry = config.registry
    introspector = registry.introspector

    def factory(context):
        return auth_policy

    def register(ctx):
        # a policy can be overriden for a context
        old_factory = registry.adapters.lookup([implementedBy(ctx)],
                                               IAuthenticationPolicy)

        if old_factory:
            adapter = old_factory(None)
            log.debug('unregister adapter=%s required=%s provided=%s',
                      adapter, [ctx], IAuthenticationPolicy)

            registry.unregisterAdapter(old_factory, required=[ctx],
                                       provided=IAuthenticationPolicy)

            policy_intr = introspector.get(intr_category, adapter)
            if policy_intr:
                policy_intr['contexts'].remove(ctx)
                if not policy_intr['contexts']:
                    introspector.remove(intr_category, adapter)

        log.debug('register adapter=%s required=%s provided=%s',
                  auth_policy, [ctx], IAuthenticationPolicy)

        registry.registerAdapter(factory, required=[ctx],
                                 provided=IAuthenticationPolicy)

    # add introspectable for policy
    policy_intr = introspector.get(intr_category, auth_policy)
    if not policy_intr:
        policy_intr = config.introspectable(
            category_name=intr_category,
            discriminator=auth_policy,
            title=auth_policy,
            type_name='authentication policy',
        )
        policy_intr['policy'] = auth_policy
        policy_intr['contexts'] = []
        log.debug('add introspectable %s', policy_intr)

    policy_intr['contexts'].extend(context_cls_list)

    for ctx in context_cls_list:
        config.action(ctx, register, args=(ctx, ),
                      introspectables=(policy_intr, ))


def get_authentication_policy(config):
    return config.registry.getUtility(IAuthenticationPolicy)


class IContextBasedAuthenticationPolicy(IAuthenticationPolicy):

    def register_policy(self, auth_policy, context):
        ""


@implementer(IContextBasedAuthenticationPolicy)
class ContextBasedAuthenticationPolicy(CallbackAuthenticationPolicy):

    def _get_policy(self, request):
        registry = request.registry
        policy = None
        for context in lineage(request.context):
            policy = registry.queryAdapter(context, IAuthenticationPolicy)
            if policy is not None:
                break
        return policy

    def _call_method(self, request, method_name, *args, **kwargs):
        policy = self._get_policy(request)
        if not policy:
            log.debug('No authentication policy for context=%s',
                      request.context)
            return None
        try:
            method = getattr(policy, method_name)
        except (KeyError, AttributeError):
            log.debug('No method: policy=%s method=%s context=%s',
                      policy, method_name, request.context)
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
