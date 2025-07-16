import shelve
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
from loguru import logger

class CacheManager:
    """
    A simple persistent, time-aware cache manager using Python's shelve module.
    """

    def __init__(self, cache_dir: str = 'data/cache', cache_name: str = 'enrichment_cache'):
        """
        Initializes the CacheManager.

        Args:
            cache_dir: The directory to store cache files.
            cache_name: The base name for the cache file.
        """
        self.cache_path = Path(cache_dir) / cache_name
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logger.bind(module=__name__)
        self.logger.info(f"Cache initialized at: {self.cache_path}")

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieves an item from the cache if it exists and is not expired.

        Args:
            key: The key of the item to retrieve.

        Returns:
            The cached value, or None if not found or expired.
        """
        with shelve.open(str(self.cache_path)) as db:
            cached_item = db.get(key)
            if not cached_item:
                return None

            value = cached_item.get('value')
            expiry = cached_item.get('expiry')

            if expiry and datetime.now() > expiry:
                self.logger.trace(f"Cache expired for key: {key}")
                # Clean up expired key
                del db[key]
                return None
            
            self.logger.trace(f"Cache hit for key: {key}")
            return value

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        """
        Sets an item in the cache with an optional time-to-live (TTL).

        Args:
            key: The key of the item to set.
            value: The value to cache.
            ttl_seconds: Optional time-to-live in seconds. If None, the item
                         will not expire.
        """
        expiry = None
        if ttl_seconds is not None:
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
        
        with shelve.open(str(self.cache_path)) as db:
            db[key] = {'value': value, 'expiry': expiry}
        self.logger.trace(f"Cache set for key: {key}")

    def close(self):
        """
        Closes the cache. Should be called on application shutdown.
        """
        # Shelve doesn't require an explicit close when used with 'with' statement.
        # This method is here for API consistency if we switch to another backend.
        self.logger.info("Cache operations finished.")
        pass
