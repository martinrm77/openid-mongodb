"""MongoDB Store

This back-end is heavily based on the RedisStore from the openid-redis package.
"""
import time, logging
from openid.store import nonce
from openid.store.interface import OpenIDStore
from openid.association import Association
import pymongo
#from pymongo.errors import DuplicateKeyError, AutoReconnect

log = logging.getLogger(__name__)

__all__ = ["MongoDBStore"]

def auto(call):
    ''' Function to automatically reconnect if theres a
    mongo auto-reconnect error'''
    logme = logging.getLogger(__name__)
    for i in xrange(6):
        try:
            return call
        except pymongo.errors.AutoReconnect:
            logme.warning('Reconnect to mongodb')
            time.sleep(pow(2,i))
    logme.error('Cannot reconnect to mongodb')
    raise Exception("Lost connection to mongodb")


class MongoDBStore(OpenIDStore):

    def __init__(self,
                 host="localhost",
                 db=None,
                 username=None,
                 password=None,
                 associations_collection="associations",
                 nonces_collection="nonces",
                 **kwargs):
        self._conn = pymongo.MongoClient(host, **kwargs)
        if host.startswith('mongodb://'):
            parsed_uri = pymongo.uri_parser.parse_uri(host)
            db = parsed_uri['database'] or db
            username = parsed_uri['username'] or username
            password = parsed_uri['password'] or password
        if db:
            self._db = self._conn[db]
        else:
            raise Exception("No mongodb database passed!")
        if username:
            self._db.authenticate(username, password)
        self.associations = self._db[associations_collection]
        self.nonces = self._db[nonces_collection]
        self.log_debug = logging.DEBUG >= log.getEffectiveLevel()
        super(MongoDBStore, self).__init__()

    def storeAssociation(self, server_url, association):
        if self.log_debug:
            log.debug("Storing association for server_url: %s, with handle: %s",
                      server_url, association.handle)
        if server_url.find('://') == -1:
            raise ValueError('Bad server URL: %r' % server_url)
        auto(self.associations.insert({
            "_id": hash((server_url, association.handle)),
            "server_url": server_url,
            "handle": association.handle,
            "association": association.serialize(),
            "expires": time.time() + association.expiresIn
        }))

    def getAssociation(self, server_url, handle=None):
        if self.log_debug:
            log.debug("Association requested for server_url: %s, with handle: %s",
                      server_url, handle)
        if server_url.find('://') == -1:
            raise ValueError('Bad server URL: %r' % server_url)
        if handle is None:
            associations = auto(self.associations.find({
                "server_url": server_url
            }))
            if associations.count():
                associations = [Association.deserialize(a['association'])
                                for a in associations]
                # Now use the one that was issued most recently
                associations.sort(cmp=lambda x, y: cmp(x.issued, y.issued))
                log.debug("Most recent is %s", associations[-1].handle)
                return associations[-1]
        else:
            association = auto(self.associations.find_one({
                "_id": hash((server_url, handle)),
                "server_url": server_url,
                "handle": handle
            }))
            if association:
                return Association.deserialize(association['association'])

    def removeAssociation(self, server_url, handle):
        if self.log_debug:
            log.debug('Removing association for server_url: %s, with handle: %s',
                      server_url, handle)
        if server_url.find('://') == -1:
            raise ValueError('Bad server URL: %r' % server_url)
        res = auto(self.associations.remove({"_id": hash((server_url, handle)),
                                        "server_url": server_url,
                                        "handle": handle},
                                       safe=True))
        return bool(res['n'])

    def cleanupAssociations(self):
        r = auto(self.associations.remove(
            {"expires": {"$gt": time.time()}},
            safe=True))
        return r['n']

    def useNonce(self, server_url, timestamp, salt):
        if abs(timestamp - time.time()) > nonce.SKEW:
            if self.log_debug:
                log.debug('Timestamp from current time is less than skew')
            return False

        n = hash((server_url, timestamp, salt))
        try:
            auto(self.nonces.insert({"_id": n,
                                "server_url": server_url,
                                "timestamp": timestamp,
                                "salt": salt},
                               safe=True))
        except pymongo.errors.DuplicateKeyError, e:
            if self.log_debug:
                log.debug('Nonce already exists: %s', n)
            return False
        else:
            return True

    def cleanupNonces(self):
        r = auto(self.nonces.remove(
            {"$or": [{"timestamp": {"$gt": time.time() + nonce.SKEW}},
                     {"timestamp": {"$lt": time.time() - nonce.SKEW}}]},
            safe=True))
        return r['n']
