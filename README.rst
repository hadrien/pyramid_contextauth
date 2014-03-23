pyramid_contextauth
###################


A simple pyramid extension to provides contexts based authentication policy.

Usage::

    from pyramid.security import remember, forget
    from pyramid.authentication import AuthTktAuthenticationPolicy,

    from pyramid_contextauth import authentication_policy


    def includeme(config):
        config.include('pyramid_contextauth')
        config.register_authentication_policy(
            AuthTktAuthenticationPolicy('secret'),
            Context1,
        )


    class Context1(object):
        pass


    class Context2(object):
        pass


    class Context3(object):
        pass


    @authentication_policy(Context2, Context3)
    class ContextAuthenticationPolicy(object):

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
