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
            # Convert unhashable types to hashable types for caching
            hashable_args = tuple(make_hashable(arg) for arg in args)
            hashable_kwargs = tuple(sorted((k, make_hashable(v)) for k, v in kwargs.items()))
            cache_key = (hashable_args, hashable_kwargs)
            
            if cache_key in cache._manual_cache:
                return cache._manual_cache[cache_key]
            
            result = cache(*args, **kwargs)
            cache._manual_cache[cache_key] = result
            return result

        def invalidate(*args, **kwargs):
            # Convert unhashable types to hashable types for invalidation
            hashable_args = tuple(make_hashable(arg) for arg in args)
            hashable_kwargs = tuple(sorted((k, make_hashable(v)) for k, v in kwargs.items()))
            cache_key = (hashable_args, hashable_kwargs)

            if cache_key in cache._manual_cache:
                del cache._manual_cache[cache_key]

        wrapped_func.invalidate = invalidate
        return wrapped_func
    return decorator


def make_hashable(obj):
    """Converts unhashable types (like dict) into hashable types (like tuple)."""
    if isinstance(obj, dict):
        return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
    if isinstance(obj, list):
        return tuple(make_hashable(e) for e in obj)
    if isinstance(obj, set):
        return frozenset(make_hashable(e) for e in obj)
    # Add other unhashable types as needed
    return obj

