from pyramid.authentication import (
    AuthTktAuthenticationPolicy,
    BasicAuthAuthenticationPolicy,
)


def includeme(config):
    config.include('pyramid_contextauth')
    tkt_policy = AuthTktAuthenticationPolicy('secret')
    config.register_authentication_policy(
        tkt_policy,
        Context1,
    )

    config.register_authentication_policy(
        BasicAuthAuthenticationPolicy('realm'),
        Context2,
    )

    config.register_authentication_policy(Context345Policy(),
                                          (Context3, Context4))

    config.register_authentication_policy(LocationAwarePolicy(), Root)

    config.commit()


class Context1(object):
    pass


class Context2(object):
    pass


class Context3(object):
    pass


class Context4(object):
    pass


class Context5(Context4):
    pass


class Context345Policy(object):
    """To handle Context3, Context4 and Context5
    """


class ChildContext(object):
    pass


class Root(object):
    __name__ = ''
    __parent__ = None

    def __getitem__(self, key):
        child = ChildContext()
        child.__name__ = key
        child.__parent__ = self
        return child


class LocationAwarePolicy(object):
    """To handle Root and any of its children
    """
