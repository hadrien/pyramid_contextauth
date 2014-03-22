Changelog
=========

0.3
---

* Break backward compatibility as
  ``ContextBasedAuthenticationPolicy.register_context`` now requires ``config``
  instance as first argument.
* Add a configuration directive: ``config.register_authentication_policy``.
* Use registry adpaters to register policies rather than a dict.
* Add a decorator ``authentication_policy`` to register policies when doing
  a config scan.
* ``config.register_authentication_policy`` accepts a list of contexts.

0.2
---

* Update dependencies by adding requirements files.

0.1.1
-----

* Changed ``register_context`` interface which breaks compatibility with 0.0.3

0.0.3
-----

* Commit configuration before returning from includeme.


0.0.2
-----

* When not provided, ``authenticated_userid`` and ``effective_principals`` from
  super class ``CallbackAuthenticationPolicy`` are used.


0.0.1
-----

* Initial version
