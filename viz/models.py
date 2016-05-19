# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2012, 2016  SPARTA, Inc. a Parsons Company
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

__version__ = '$Id: models.py 5497 2013-09-19 18:32:48Z melkins $'

from datetime import datetime
import time
import binascii

from django.db import models
from django.core.urlresolvers import reverse

import rpki.resource_set
import rpki.POW

def encode_ip(value):
    "convert raw bytes to string"
    return binascii.hexlify(value)

def decode_ip(value):
    "convert string to raw bytes"
    return binascii.unhexlify(value)

class URI(models.Model):
    uri = models.CharField(max_length=255, unique=True)

    def __unicode__(self):
        return u'%s' % self.uri

    def __repr__(self):
        return '<URI pk=%d uri=%s>' % (self.pk, self.uri)


class SerialNumber(models.Field):
    """field large enough to hold a 20-octet serial number"""

    def db_type(self, connection):
        return 'varchar(40)'

    def from_db_value(self, value, expression, connection, context):
        if value is None:
            return value
        return int(value, 16)

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, int):
            return value
        return '%X' % value

    def get_prep_value(self, value):
        return '%X' % value


class IPAddressField(models.Field):
    "Field large enough to hold a 128-bit unsigned integer."

    def db_type(self, connection):
        return 'varchar(32)'

    def from_db_value(self, value, expression, connection, context):
        if value is None:
            return value
        ip_version = 4 if (len(value) == 16) else 6
        return rpki.POW.IPAddress.fromBytes(decode_ip(value))

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, rpki.POW.IPAddress):
            return value
        ip_version = 4 if (len(value) == 16) else 6
        return rpki.POW.IPAddress.fromBytes(decode_ip(value))

    def get_prep_value(self, value):
        return encode_ip(value.toBytes())


class Epoch(models.Model):
    """Groups together all objects at a particular point in time."""
    when = models.DateTimeField(auto_now_add=True, db_index=True)

    def __repr__(self):
        return '<Epoch: pk=%d when=%s>' % (self.pk, self.when)

    def __unicode__(self):
        return u'%s' % str(self.when)


kinds = list(enumerate(('good', 'warn', 'bad')))
kinds_dict = dict((v, k) for k, v in kinds)


class Status(models.Model):
    """
    Represents a specific error condition defined in the rcynic XML
    output file.
    """
    label = models.CharField(max_length=79, db_index=True, unique=True)
    status = models.CharField(max_length=255)
    kind = models.PositiveSmallIntegerField(choices=kinds)

    def __unicode__(self):
        return self.label


# Validation is separated from RepositoryObject because some classes of errors
# cause the object not to be able to be parsed (e.g. missing from repository)
class Validation(models.Model):
    epoch = models.ForeignKey(Epoch, on_delete=models.CASCADE)
    uri = models.ForeignKey(URI, on_delete=models.CASCADE)
    statuses = models.ManyToManyField(Status)

    def __repr__(self):
        return '<Validation uri=%s epoch=%s>' % (self.uri, self.epoch)


class Prefix(models.Model):
    """Common implementation for models with an IP address range.
    """
    version = models.CharField(max_length=1)
    prefix_min = IPAddressField(db_index=True, null=False)
    prefix_max = IPAddressField(db_index=True, null=False)

    def as_resource_range(self):
        """
        Returns the prefix as a rpki.resource_set.resource_range_ip object.
        """
        range_cls = rpki.resource_set.resource_range_ipv4 if self.prefix_min.version == 4 else rpki.resource_set.resource_range_ipv6
        return range_cls(self.prefix_min, self.prefix_max)

    @property
    def prefixlen(self):
        "Returns the prefix length for the prefix in this object."
        return self.as_resource_range().prefixlen()

    def get_prefix_display(self):
        "Return a string representatation of this IP prefix."
        return str(self.as_resource_range())

    def __unicode__(self):
        """This method may be overridden by subclasses.  The default
        implementation calls get_prefix_display(). """
        return self.get_prefix_display()

    class Meta:
        abstract = True

        # default sort order reflects what "sh ip bgp" outputs
        ordering = ('prefix_min',)


class AddressRange(Prefix):
    pass


class ASRange(models.Model):
    """Represents a range of ASNs.
    """

    min = models.PositiveIntegerField(null=False)
    max = models.PositiveIntegerField(null=False)

    class Meta:
        ordering = ('min', 'max')

    def as_resource_range(self):
        return rpki.resource_set.resource_range_as(self.min, self.max)

    def __unicode__(self):
        return u'AS%s' % self.as_resource_range()


class TelephoneField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 255
        models.CharField.__init__(self, *args, **kwargs)


class ValidationMixin(object):
    """adds helper methods to access info from the most recent validation run"""

    def get_validation(self):
        """return the Validation from the most recent epoch"""
        return self.validation.all().order_by('-epoch__when').first()

    def get_uri(self):
        """returns the URI object for this object from the most recent epoch"""
        return self.get_validation().uri

    def get_status(self):
        """returns the list of statuses from the most recent epoch"""
        return self.get_validation().statuses.all()


class RepositoryObject(models.Model, ValidationMixin):
    """uri is not here because in theory objects could move within the repository"""
    validation = models.ManyToManyField(Validation)
    sha256 = models.SlugField()
    ski = models.SlugField()
    aki = models.SlugField(null=True)  # self-signed CA certs may exclude this
    subject_name = models.CharField(max_length=66)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    serial = SerialNumber()
    aia_uri = models.CharField(max_length=255, null=True) # not present in self-signed

    class Meta:
	abstract = True

    def __repr__(self):
        seg = [ '<%s ' % self.__class__.__name__]
        seg.extend('%s=%s' % (attr, getattr(self, attr)) for attr in self.repr_fields)
        seg.append('>')
        return ' '.join (seg)


class Manifest(RepositoryObject):
    repr_fields = ('pk', 'this_update', 'next_update', 'manifest_number')

    this_update = models.DateTimeField()
    next_update = models.DateTimeField()
    manifest_number = SerialNumber()


def current_epoch():
    return models.Epoch.objects.all().order_by('-when').first()


class ResourceCert(RepositoryObject):
    """
    Object representing a resource CA certificate.
    """
    repr_fields = ('pk', 'subject_name')

    addresses = models.ManyToManyField(AddressRange)
    asns = models.ManyToManyField(ASRange)
    inherit_asn = models.BooleanField(default=False)
    inherit_v4 = models.BooleanField(default=False)
    inherit_v6 = models.BooleanField(default=False)
    sia_directory_uri = models.ManyToManyField(URI, related_name='sia_directory_uri')
    manifest_uri = models.ManyToManyField(URI, related_name='manifest_uri')
    crldp = models.ManyToManyField(URI, related_name='crldp')

    def get_roas(self, epoch=None):
        """return a queryset of roas from the most recent epoch that derive from this rescert"""
        return ROA.objects.filter(aki=self.ski, validation__epoch=current_epoch() if epoch is None else epoch)

    def get_crls(self, epoch=None):
        """return a queryset of crls from the most recent epoch that derive from this rescert"""
        return CRL.objects.filter(aki=self.ski, validation__epoch=current_epoch() if epoch is None else epoch)

    def get_mfts(self, epoch=None):
        """return a queryset of mfts from the most recent epoch that derive from this rescert"""
        return Manifest.objects.filter(aki=self.ski, validation__epoch=current_epoch() if epoch is None else epoch)

    def get_gbrs(self, epoch=None):
        """return a queryset of mfts from the most recent epoch that derive from this rescert"""
        return Ghostbuster.objects.filter(aki=self.ski, validation__epoch=current_epoch() if epoch is None else epoch)


class ROAPrefix(Prefix):
    max_length = models.PositiveSmallIntegerField()

    def as_roa_prefix(self):
        "Return value as a rpki.resource_set.roa_prefix_ip object."
        rng = self.as_resource_range()
        roa_cls = resource_set.roa_prefix_ipv4 if self.version == '4' else resource_set.roa_prefix_ipv6
        return roa_cls(rng.min, rng.prefixlen(), self.max_length)

    def __unicode__(self):
        p = self.as_resource_range()
        if p.prefixlen() == self.max_length:
            return str(p)
        return '%s-%s' % (str(p), self.max_length)

    class Meta:
        ordering = ('prefix_min',)


class ROA(RepositoryObject):
    asid = models.PositiveIntegerField()
    prefixes = models.ManyToManyField(ROAPrefix, related_name='roas')

    class Meta:
        ordering = ('asid',)

    def __unicode__(self):
        return u'ROA for AS%d' % self.asid


class Ghostbuster(RepositoryObject):
    full_name = models.CharField(max_length=40)
    email_address = models.EmailField(blank=True, null=True)
    organization = models.CharField(blank=True, null=True, max_length=255)
    telephone = TelephoneField(blank=True, null=True)

    def __unicode__(self):
        if self.full_name:
            return self.full_name
        if self.organization:
            return self.organization
        if self.email_address:
            return self.email_address
        return self.telephone


class CRL(models.Model, ValidationMixin):
    validation = models.ManyToManyField(Validation)
    sha256 = models.SlugField()
    this_update = models.DateTimeField()
    next_update = models.DateTimeField()
    aki = models.SlugField()
    crl_number = SerialNumber()

    def __repr__(self):
        return '<CRL uri=%s>' % self.get_uri()

# vim:sw=4 expandtab
