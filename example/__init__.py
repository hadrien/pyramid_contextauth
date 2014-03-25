from pyramid.authentication import (
    AuthTktAuthenticationPolicy,
    BasicAuthAuthenticationPolicy,
)

from pyramid_contextauth import authentication_policy


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

    config.scan()

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


class ToBeRemovedPolicy(object):
    pass


@authentication_policy(contexts=(Context3, Context4))
class Context345Policy(object):
    pass
