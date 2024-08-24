from functools import lru_cache, wraps

def parameterized_lru_cache(maxsize=128):
    """
    A decorator that provides an LRU (Least Recently Used) cache for a function, with support for
    selective cache invalidation based on specific function arguments.

    I wrote this because I didn't want to add additional dependencies to my project, and this allows me 
    to selectively invalidate parts a cache storing a list of documents in each stage of approval, based
    on the params passed to the function.

    This decorator is ideal for use cases where you want to cache the results of a function based on
    certain parameters and have the ability to invalidate the cache for specific combinations of 
    those parameters without affecting the rest of the cached data.
    """

    def decorator(func):
        cache = lru_cache(maxsize=maxsize)(func)
        cache._manual_cache = {}

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            # Custom key generation based on args (form_name, stage_name) and kwargs
            form_name = kwargs.get('form_name') or args[0]
            stage_name = kwargs.get('stage_name') or None
            cache_key = (form_name, stage_name)
            
            if cache_key in cache._manual_cache:
                return cache._manual_cache[cache_key]
            
            result = cache(*args, **kwargs)
            cache._manual_cache[cache_key] = result
            return result

        def invalidate(form_name, stage_name):
            # Invalidate specific cache entries based on form_name and stage_name
            cache_key = (form_name, stage_name)
            if cache_key in cache._manual_cache:
                del cache._manual_cache[cache_key]

        wrapped_func.invalidate = invalidate
        return wrapped_func
    return decorator