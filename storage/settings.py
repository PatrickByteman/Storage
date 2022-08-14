LOCAL = 0
if LOCAL:
    from .local_settings import *
else:
    from .production_settings import *
