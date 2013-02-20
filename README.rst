pyramid_contextauth
###################

A simple pyramid extension to provides contexts based authentication policy.
To register authentication methods::

    from pyramid.security import remember, forget


    class Context(object):
        pass


    class ContextAuthenticationPolicy:
        def authenticated_userid(self, request):
            return unauthenticated_userid(request)

        def unauthenticated_userid(self, request):
            "A dummy example"
            return request.POST.get('userid')

        def effective_principals(self, request):
            if self.unauthenticated_userid(request):
                return ['User']
            return []

        def remember(self, request, prinicpal, **kw):
            return remember(request, prinicpal, **kw)

        def forget(self, request):
            return forget(request)


    def includeme(config):
        from pyramid_contextauth import get_authentication_policy
        policy = get_authentication_policy(config)
        policy.register_context(Context, ContextAuthenticationPolicy)


