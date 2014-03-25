import unittest

import mock

from pyramid.config import Configurator, ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy

from zope.interface import implementedBy


class TestConfig(unittest.TestCase):

    def _get_config(self):
        config = Configurator(settings={})
        config.include('pyramid_contextauth')
        return config

    def test_get_policy(self):
        from pyramid_contextauth import (
            get_authentication_policy,
            ContextBasedAuthenticationPolicy,
            )
        config = self._get_config()
        config.commit()
        policy = get_authentication_policy(config)
        self.assertIsInstance(policy, ContextBasedAuthenticationPolicy)


class TestPyramidContextAuth(unittest.TestCase):

    def setUp(self):
        self.config = Configurator(settings={})
        self.config.include('pyramid_contextauth')

    def _get_policy(self):
        from pyramid_contextauth import get_authentication_policy
        return get_authentication_policy(self.config)

    def _get_context_class(self, name):
        return type(name, (object, ), {})

    def test_call_method_no_context(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        policy = self._get_policy()

        self.assertIsNone(policy._call_method(request, 'authenticated_userid'))

    def test_call_method_no_authenticated_userid_method(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        ctx_policy = type('Policy', (object, ), {})

        policy = self._get_policy()

        self.config.register_authentication_policy(ctx_policy, A)
        self.config.commit()

        self.assertEqual(None, policy.authenticated_userid(request))

    def test_call_method_no_effective_principals(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        ctx_policy = type('Policy', (object, ), {})

        policy = self._get_policy()

        self.config.register_authentication_policy(ctx_policy, A)
        self.config.commit()

        self.assertEqual(['system.Everyone'],
                         policy.effective_principals(request))

    def test_authenticated_methods(self):
        A = self._get_context_class('A')
        ctx_policy = mock.Mock()
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        policy = self._get_policy()

        self.config.register_authentication_policy(ctx_policy, A)
        self.config.commit()

        self.assertEqual(ctx_policy.authenticated_userid.return_value,
                         policy.authenticated_userid(request))

        self.assertEqual(ctx_policy.unauthenticated_userid.return_value,
                         policy.unauthenticated_userid(request))

    def test_effective_principals(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        ctx_policy = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        policy = self._get_policy()

        ctx_policy.unauthenticated_userid.return_value = '123'
        ctx_policy.effective_principals.return_value = ['1234567']

        self.config.register_authentication_policy(ctx_policy, A)
        self.config.commit()

        expected = ['system.Everyone', 'system.Authenticated', '123',
                    '1234567']
        self.assertEqual(expected, policy.effective_principals(request))

    def test_remember_forget(self):
        A = self._get_context_class('A')
        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry
        policy = self._get_policy()

        ctx_policy = mock.Mock()
        ctx_policy.forget.return_value = ['Header']
        ctx_policy.remember.return_value = ['Header']

        self.config.register_authentication_policy(ctx_policy, A)
        self.config.commit()

        self.assertEqual(['Header'],
                         policy.remember(request,
                                         ['system.Everyone', '1234567']))
        self.assertEqual(['Header'], policy.forget(request))

    def test_override_configuration_error(self):
        A = self._get_context_class('A')

        ctx_policy1 = mock.Mock()
        ctx_policy2 = mock.Mock()

        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        self.config.register_authentication_policy(ctx_policy1, A)
        self.config.register_authentication_policy(ctx_policy2, A)

        with self.assertRaises(ConfigurationError):
            self.config.commit()

    def test_override(self):
        A = self._get_context_class('A')

        ctx_policy1 = mock.Mock()
        ctx_policy2 = mock.Mock()

        request = mock.Mock()
        request.context = A()
        request.registry = self.config.registry

        registry = self.config.registry
        introspector = registry.introspector
        intr_category = 'context based authentication policies'

        self.config.register_authentication_policy(ctx_policy1, A)
        self.config.commit()

        ctx_policy1_factory = registry.adapters.lookup([implementedBy(A)],
                                                       IAuthenticationPolicy)

        self.config.register_authentication_policy(ctx_policy2, A)
        self.config.commit()

        # Make sure ctx_policy1 is not looked up
        adapter_factory = registry.adapters.lookup([implementedBy(A)],
                                                   IAuthenticationPolicy)
        self.assertIs(adapter_factory(None), ctx_policy2)

        # Make sure ctx_policy1 does not appear in introspectable
        intr = introspector.get(intr_category, ctx_policy1_factory)
        self.assertIsNone(intr)

        intr_category = introspector.get_category(intr_category)
        self.assertEqual(1, len(intr_category))

        intr = intr_category[0]['introspectable']
        self.assertEqual(ctx_policy2, intr.discriminator)
