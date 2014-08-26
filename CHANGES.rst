Changelog
=========

0.7
---

* Policy checks on each resource lineage and get the first policy it gets.
* Add coverall in after_success of travis config.
* Remove pyramid version constraints.

0.6
---

* Removing decorator ``authentication_policy``: extension should not
  instantiate authentication policy class internally.

0.5
---

* Registering same context to multiple policies raises a configuration error.
* Unregister old policy when overriding a context with another policy.
* Change register_authentication_policy and authentication_policy signatures.

0.4
---

* Add introspectables to config for registered authentication policies.
* Rename register_context to register_policy

0.3
---

* Break backward compatibility as
  ``ContextBasedAuthenticationPolicy.register_context`` now requires ``config``
  instance as first argument.
* Add ``config.register_authentication_policy`` configuration directive which
  accepts a list of contexts.
* Use registry adpaters to register policies rather than a dict.
* Add a decorator ``authentication_policy`` to register policies when doing
  a config scan.

0.2.1
-----

* Adjust requirements files and dependencies.

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
