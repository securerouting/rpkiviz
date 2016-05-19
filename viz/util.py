# Copyright (C) 2011  SPARTA, Inc. dba Cobham
# Copyright (C) 2012, 2013, 2016  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__version__ = '$Id: util.py 5850 2014-05-30 04:09:54Z sra $'
__all__ = ('import_rcynic_xml')

default_logfile = '/var/rcynic/data/rcynic.xml'
default_root = '/var/rcynic/data'

import time
import vobject
import logging
import os
import hashlib
import urlparse

import django.db.models
from django.db import transaction

import rpki
from viz import models
from rpki.rcynic import rcynic_xml_iterator, label_iterator

logger = logging.getLogger(__name__)

class rcynic_object(object):
    def __init__(self, *args, **kwargs):
        self.der = args[0]
        self.epoch = kwargs['epoch']
        self.attrs = {
                'sha256': kwargs['sha256'],
                'aki': ''.join(x for x in self.der.aki if x != ':')
        }

    def create(self):
        self.obj =  self.model.objects.create(**self.attrs)

    def post(self):
        pass

    def __call__(self):
        self.create()
        self.post()
        return self.obj


class rcynic_cert(rcynic_object):
    def __init__(self, *args, **kwargs):
        rcynic_object.__init__(self, *args, **kwargs)

        self.attrs['not_before'] = self.der.notBefore
        self.attrs['not_after'] = self.der.notAfter
        self.attrs['subject_name'] = self.der.subject
        self.attrs['aia_uri'] = self.der.aia_uri
        self.attrs['ski'] = ''.join(x for x in self.der.ski if x != ':')
        self.attrs['serial'] = self.der.serial


class rcynic_resource_cert(rcynic_cert):
    model = models.ResourceCert

    def __init__(self, *args, **kwargs):
        rcynic_cert.__init__(self, *args, **kwargs)
        self.attrs['inherit_asn'] = self.der.resources.asn.inherit
        self.attrs['inherit_v4'] = self.der.resources.v4.inherit
        self.attrs['inherit_v6'] = self.der.resources.v6.inherit

    def post(self):
        cert = self.der

        for u in cert.sia_directory_uri:
            uri, created = models.URI.objects.get_or_create(uri=u)
            self.obj.sia_directory_uri.add(uri)

        for u in cert.manifest_uri:
            uri, created = models.URI.objects.get_or_create(uri=u)
            self.obj.manifest_uri.add(uri)

        if cert.crldp:
            for u in cert.crldp:
                uri, created = models.URI.objects.get_or_create(uri=u)
                self.obj.crldp.add(uri)

        if not cert.resources.asn.inherit:
            for asr in cert.resources.asn:
                logger.debug('processing %s', asr)

                attrs = {'min': asr.min, 'max': asr.max}
                q = models.ASRange.objects.filter(**attrs)
                if not q:
                    self.obj.asns.create(**attrs)
                else:
                    self.obj.asns.add(q[0])

        for ipver, addrset in ('4', cert.resources.v4), ('6', cert.resources.v6):
            if not addrset.inherit:
                for rng in addrset:
                    logger.debug('processing %s', rng)

                    attrs = {'version': ipver, 'prefix_min': rng.min, 'prefix_max': rng.max}
                    q = models.AddressRange.objects.filter(**attrs)
                    if not q:
                        self.obj.addresses.create(**attrs)
                    else:
                        self.obj.addresses.add(q[0])


class rcynic_roa(rcynic_cert):
    model = models.ROA

    def __init__(self, *args, **kwargs):
        rcynic_cert.__init__(self, *args, **kwargs)
        self.attrs['asid'] = self.der.asID

    def post(self):
        for pfxset in self.der.prefix_sets:
            for pfx in pfxset:
                attrs = {'version': str(pfx.min().version),
                         'prefix_min': pfx.min(),
                         'prefix_max': pfx.max(),
                         'max_length': pfx.max_prefixlen}
                q = models.ROAPrefix.objects.filter(**attrs)
                if not q:
                    self.obj.prefixes.create(**attrs)
                else:
                    self.obj.prefixes.add(q[0])


class rcynic_gbr(rcynic_cert):
    model = models.Ghostbuster

    def __init__(self, *args, **kwargs):
        rcynic_cert.__init__(self, *args, **kwargs)

        vcard = vobject.readOne(self.der.vcard)

        self.attrs['full_name'] = vcard.fn.value if hasattr(vcard, 'fn') else None
        self.attrs['email_address'] = vcard.email.value if hasattr(vcard, 'email') else None
        self.attrs['telephone'] = vcard.tel.value if hasattr(vcard, 'tel') else None
        self.attrs['organization'] = vcard.org.value[0] if hasattr(vcard, 'org') else None


class rcynic_manifest(rcynic_cert):
    model = models.Manifest

    def __init__(self, *args, **kwargs):
        rcynic_cert.__init__(self, *args, **kwargs)
        self.attrs['manifest_number'] = self.der.manifestNumber
        self.attrs['this_update'] = self.der.thisUpdate
        self.attrs['next_update'] = self.der.nextUpdate


class rcynic_crl(rcynic_object):
    model = models.CRL

    def __init__(self, *args, **kwargs):
        rcynic_object.__init__(self, *args, **kwargs)
        self.attrs['this_update'] = self.der.thisUpdate
        self.attrs['next_update'] = self.der.nextUpdate
        self.attrs['crl_number'] = self.der.crlNumber


dispatch = {
    'rcynic_certificate': rcynic_resource_cert,
    'rcynic_roa': rcynic_roa,
    'rcynic_ghostbuster': rcynic_gbr,
    'rcynic_manifest': rcynic_manifest,
    'rcynic_crl': rcynic_crl,
}

model_map = {
    'rcynic_certificate': models.ResourceCert,
    'rcynic_roa': models.ROA,
    'rcynic_ghostbuster': models.Ghostbuster,
    'rcynic_manifest': models.Manifest,
    'rcynic_crl': models.CRL,
}

file_exts = ('cer', 'roa', 'gbr', 'crl', 'mft', 'gbr')


@transaction.atomic
def process_cache(root, xml_file):
    epoch = models.Epoch.objects.create()

    logger.info('updating validation status')

    last_uri = None
    last_filename = None

    for vs in rcynic_xml_iterator(root, xml_file):
	try:
            # We don't need to store backup objects because we already keep history
            if vs.generation == 'backup':
                continue

            # entries in the xml file are mostly grouped by uri
            if vs.uri != last_uri:
                uri, created = models.URI.objects.get_or_create(uri=vs.uri)
                validation, created = models.Validation.objects.get_or_create(epoch=epoch, uri=uri)
                last_uri = vs.uri

            status = models.Status.objects.get(label=vs.status)
            validation.statuses.add(status)

            if not hasattr(vs, 'file_class'):
                logger.debug('no file_class for uri=%s status=%s', vs.uri, vs.status)
                continue

            # make sure we read each file just once
            if vs.filename != last_filename:
                logger.debug('processing %s', vs.filename)
                last_filename = vs.filename
                try:
                    m = hashlib.sha256()
                    with open(vs.filename) as f:
                        m.update(f.read())
                    csum = m.hexdigest()

                    cls = model_map[vs.file_class.__name__]
                    obj = cls.objects.filter(sha256=csum).first()
                    if obj:
                        # cache hit
                        logger.debug('cache hit for uri=%s' % vs.uri)
                    else:
                        der = vs.get_obj()  # parse object

                        cls = dispatch[vs.file_class.__name__]
                        handler = cls(der, uri=uri, epoch=epoch, sha256=csum)
                        obj = handler()

                    obj.validation.add(validation)
                except IOError as err:
                    logger.warning('caught exception while trying to read %s', vs.filename)
                    logger.exception(err)

	except Exception as err:
	    logger.error('caught exception while processing uri=%s filename=%s status=%s', vs.uri, vs.filename, vs.status)
	    raise

def process_labels(xml_file):
    logger.info('updating labels...')

    for label, kind, desc in label_iterator(xml_file):
        logger.debug('label=%s kind=%s desc=%s', label, kind, desc)
        if kind:
            models.Status.objects.get_or_create(label=label, defaults={'status': desc, 'kind': models.kinds_dict[kind]})


def import_rcynic_xml(root=default_root, logfile=default_logfile):
    """Load the contents of rcynic.xml into the rpki.gui.cacheview database."""

    start = time.time()
    process_labels(logfile)
    process_cache(root, logfile)
    stop = time.time()
    logger.info('elapsed time %d seconds.', (stop - start))

# vim:sw=4 expandtab
