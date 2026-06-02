import warnings

warnings.warn(
    "mod_wsgi.server is deprecated; use mod_wsgi.express instead. "
    "If 'mod_wsgi.server' appears in Django INSTALLED_APPS, change it "
    "to 'mod_wsgi.express'.",
    FutureWarning, stacklevel=2,
)
