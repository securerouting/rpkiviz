# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2013, 2016  SPARTA, Inc. a Parsons Company
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

__version__ = '$Id: views.py 5496 2013-09-19 16:25:32Z melkins $'

from django.views.generic import DetailView
from django.shortcuts import render
from django.core.urlresolvers import reverse
import django.http

from viz import models, forms, misc
from rpki.resource_set import resource_range_as, resource_range_ip
from rpki.exceptions import BadIPResource

import gv
import urlparse
import re

import logging

logger = logging.getLogger(__name__)

def cert_chain(epoch, obj):
    """
    returns an iterator covering all certs from the root cert down to the EE.
    """
    chain = [obj]
    while obj.aki:
        obj = models.ResourceCert.objects.get(validation__epoch__pk=epoch, ski=obj.aki)
        chain.append(obj)
    return zip(range(len(chain)), reversed(chain))


class SignedObjectDetailView(DetailView):
    def get_context_data(self, **kwargs):
        context = super(SignedObjectDetailView, self).get_context_data(**kwargs)
        context['chain'] = cert_chain(self.kwargs['epoch'], self.object)
        context['epoch'] = models.Epoch.objects.get(pk=self.kwargs['epoch'])
        context['validation'] = self.object.validation.get(epoch=context['epoch'])
        return context


class RoaDetailView(SignedObjectDetailView):
    model = models.ROA


class CertDetailView(SignedObjectDetailView):
    def get_context_data(self, **kwargs):
        context = super(CertDetailView, self).get_context_data(**kwargs)
        # List of invalid child objects
        context['invalid'] = context['epoch'].validation_set.filter(uri__startswith=self.object.sia).exclude(statuses__label='object_accepted').exclude(uri__regex=r'%s.*/.*' % (self.object.sia,))
        context['children'] = models.ResourceCert.objects.filter(validation__epoch=context['epoch'], aki=self.object.ski)
        context['roas'] = models.ROA.objects.filter(validation__epoch=context['epoch'], aki=self.object.ski)
        context['ghostbusters'] = models.Ghostbuster.objects.filter(validation__epoch=context['epoch'], aki=self.object.ski)
        return context

    model = models.ResourceCert


class GhostbusterDetailView(SignedObjectDetailView):
    model = models.Ghostbuster



def search_view(request):
    certs = None
    roas = None

    if request.method == 'POST':
        form = forms.SearchForm(request.POST, request.FILES)
        if form.is_valid():
            r = form.cleaned_data.get('resource')
            return django.http.HttpResponseRedirect(reverse('prefix-graph', args=[str(r.min), str(r.prefixlen())]))
    else:
        form = forms.SearchForm()

    return render(request, 'viz/search_result.html', {'form': form})


def global_summary(request, **kwargs):
    """Display a table summarizing the state of the global RPKI."""

    epoch = models.Epoch.objects.all().order_by('-when').first()
    roots = models.ResourceCert.objects.filter(validation__epoch=epoch, aki='')  # self-signed

    return render(request, 'cacheview/global_summary.html', {
        'roots': roots,
        'epoch': epoch
    })


def prefix_view(request, network, mask):
    """Summary view of network/mask prefix"""

    s = '%s/%s' % (network, mask)
    rng = resource_range_ip.parse_str(s)

    epoch_list = []
    # For each epoch, determine if this prefix is covered by a ROA
    for epoch in models.Epoch.objects.all().order_by('-when')[:24]:
        roa_list = list(models.ROA.objects.filter(validation__epoch=epoch, prefixes__prefix_min__lte=rng.min, prefixes__prefix_max__gte=rng.max))
        if roa_list:
            epoch.status = 'covered'
        else:
            epoch.status = 'uncovered'
        epoch.roa_list = roa_list

        # sort so that the most specific match is listed first, which should be the last resource holder the prefix is delegated to
        epoch.cert_list = models.ResourceCert.objects.filter(validation__epoch=epoch, addresses__version=rng.version, addresses__prefix_min__lte=rng.min, addresses__prefix_max__gte=rng.max).order_by('-addresses__prefix_min', 'addresses__prefix_max')

        epoch_list.append(epoch)

    return render(request, 'cacheview/prefix_view.html', {'epoch_list': epoch_list, 'prefix': s})

def expire_view(request):
    epoch = models.Epoch.objects.all().order_by('-when').first()
    kw = { 'certs': models.ResourceCert.objects.filter(validation__epoch=epoch).order_by('not_after')[:10],
            'roas': models.ROA.objects.filter(validation__epoch=epoch).order_by('not_after')[:10],
            'epoch': epoch }
    return render(request, 'cacheview/expire_view.html', kw)

width_re = re.compile(r'width="(\d+)')

def make_svg(g):
    gv.layout(g, 'dot')
    svg = gv.renderdata(g, 'svg')
    # remove the xml header to leave only the raw svg object which will be embedded
    s = svg.split('\n')
    for n in range(len(s)):
        if s[n].startswith('<svg'):
            # if the image is larger than 960px, scale the image to fit the width of the display
            # ugly hack, but apparently the only way to get this to scale properly
            m = width_re.search(s[n])
            if m and int(m.group(1)) > 960:
                s[n] = '<svg width="100%"'
            break
    return '\n'.join(s[n:])

def set_status_color(node, validation):
    kind_set = set(s.get_kind_display() for s in validation.statuses.all())
    gv.setv(node, 'style', 'filled')
    if 'bad' in kind_set:
        gv.setv(node, 'fillcolor', 'red')
    elif 'warn' in kind_set:
        gv.setv(node, 'fillcolor', 'yellow')
    else:
        gv.setv(node, 'fillcolor', 'green')

def browse_cert(request, pk, **kwargs):
    if 'epoch' in kwargs:
        epoch = models.Epoch.objects.get(pk=int(kwargs['epoch']))
    else:
        epoch = models.Epoch.objects.order_by('-when').first()
    cert = models.ResourceCert.objects.get(pk=int(pk))
    cert_validation = cert.validation.get(epoch=epoch)
    cert_uri = cert_validation.uri

    g = gv.digraph('RPKI')

    # use subgraphs to denote repositories
    # clusters must be named with the cluster_ prefix
    subgraph_map = {}

    def subgraph(uri):
        if uri is None:
            return g
        r = urlparse.urlparse(uri.uri)
        if r.hostname not in subgraph_map:
            name = 'cluster_%d' % (len(subgraph_map.keys()))
            subgraph_map[r.hostname] = gv.graph(g, name)
            gv.setv(subgraph_map[r.hostname], 'label', str(r.hostname))
            gv.setv(subgraph_map[r.hostname], 'color', 'blue')
        return subgraph_map[r.hostname]

    if cert.aki:
        name = 'cert-%d' % cert.pk
    else:
        # use hostname for TAs
        r = urlparse.urlparse(cert_uri.uri)
        name = str(r.hostname)

    n = gv.node(subgraph(cert_uri), name)
    gv.setv(n, 'id', 'cert-%d' % cert.pk)
    set_status_color(n, cert_validation)

    certs = [cert]

    # add children
    children = models.ResourceCert.objects.filter(validation__epoch=epoch, aki=cert.ski)
    for child in children:
        child_validation = child.validation.get(epoch=epoch)
        child_uri = child_validation.uri
        name = 'cert-%d' % child.pk
        p = gv.node(subgraph(child_uri), name)
        gv.setv(p, 'href', str(reverse('browse-cert-epoch', args=[epoch.pk, child.pk])))
        gv.setv(p, 'id', name)
        e = gv.edge(n, p)
        #gv.setv(e, 'color', 'blue')
        certs.append(child)
        set_status_color(p, child_validation)

    # add ROAs
    roas = models.ROA.objects.filter(validation__epoch=epoch, aki=cert.ski)
    for roa in roas:
        roa_validation = roa.validation.get(epoch=epoch)
        roa_uri = roa_validation.uri
        name = 'roa-' + str(roa.pk)
        p = gv.node(subgraph(roa_uri), name)
        gv.setv(p, 'id', name)
        gv.setv(p, 'shape', 'rectangle')
        set_status_color(p, roa_validation)
        gv.edge(n, p)

    # add gbrs
    gbrs = models.Ghostbuster.objects.filter(validation__epoch=epoch, aki=cert.ski)
    for gbr in gbrs:
        gbr_validation = gbr.validation.get(epoch=epoch)
        gbr_uri = gbr_validation.uri
        name = 'gbr-' + str(gbr.pk)
        p = gv.node(subgraph(gbr_uri), name)
        gv.setv(p, 'id', name)
        gv.setv(p, 'shape', 'rectangle')
        gv.edge(n, p)
        set_status_color(p, gbr_validation)

    # manifest
    mft_uri = cert.manifest_uri.all()[0]
    mfts = []
    for mft in models.Manifest.objects.filter(validation__epoch=epoch, aki=cert.ski):
        mft_validation = mft.validation.get(epoch=epoch)
        mftnode = gv.node(subgraph(mft_uri), 'mft-%d' % mft.pk)
        gv.edge(n, mftnode)
        gv.setv(mftnode, 'shape', 'rectangle')
        gv.setv(mftnode, 'id', 'mft-%d' % mft.pk)
        set_status_color(mftnode, mft_validation)
        mfts.append(mft)

    # CRL
    crls = []
    for crl in models.CRL.objects.filter(validation__epoch=epoch, aki=cert.ski):
        crl_validation = crl.validation.get(epoch=epoch)
        crl_uri = crl_validation.uri
        crlnode = gv.node(subgraph(crl_uri), 'crl-%d' % crl.pk)
        gv.setv(crlnode, 'id', 'crl-%d' % crl.pk)
        gv.setv(crlnode, 'shape', 'rectangle')
        gv.edge(n, crlnode)
        set_status_color(crlnode, crl_validation)
        crls.append(crl)

    # build cert hierarchy
    while cert.aki:
        cert = models.ResourceCert.objects.get(validation__epoch=epoch, ski=cert.aki)
        cert_validation = cert.validation.get(epoch=epoch)
        cert_uri = cert_validation.uri
        if not cert.aki:
            r = urlparse.urlparse(cert_uri.uri)
            name = str(r.hostname)
        else:
            name = 'cert-' + str(cert.pk)
        p = gv.node(subgraph(cert_uri), name)
        gv.setv(p, 'href', str(reverse('browse-cert-epoch', args=[epoch.pk, cert.pk])))
        gv.setv(p, 'id', 'cert-%d' % cert.pk)
        e = gv.edge(p, n)
        #gv.setv(e, 'color', 'blue')
        n = p
        certs.append(cert)
        set_status_color(p, cert_validation)

    svg = make_svg(g)

    return render(request, 'viz/browse.html', {
        'svg': svg, 'epoch': epoch, 'certs': certs, 'roas': roas, 'gbrs': gbrs, 'mfts': mfts, 'crls': crls
        })

def browse(request, **kwargs):
    """display graph of TAs"""
    epoch = models.Epoch.objects.all().order_by('-when').first()
    roots = models.ResourceCert.objects.filter(validation__epoch=epoch, aki='')  # self-signed

    g = gv.digraph('RPKI')
    certs = []
    for n in roots:
        r = urlparse.urlparse(n.get_uri().uri)

        gn = gv.node(g, str(r.hostname))
        gv.setv(gn, 'href', str(reverse('browse-cert', args=[epoch.pk, n.pk])))
        gv.setv(gn, 'id', 'cert-%d' % n.pk)
        certs.append(n)

    svg = make_svg(g)

    return render(request, 'viz/browse.html', {'svg': svg, 'epoch': epoch, 'certs': certs})

def make_node(obj, name, epoch, parent_node, subgraph, shape=None):
    obj_validation = obj.validation.get(epoch=epoch)
    obj_uri = obj_validation.uri
    obj_name = '%s-%d' % (name, obj.pk)
    obj_node = gv.node(subgraph(obj_uri), obj_name)
    gv.setv(obj_node, 'id', obj_name)
    if name == 'cert':
        gv.setv(obj_node, 'href', str(reverse('browse-cert', args=[obj.pk])))
    if shape:
        gv.setv(obj_node, 'shape', shape)
    set_status_color(obj_node, obj_validation)
    if parent_node:
        e = gv.edge(parent_node, obj_node)
    return obj_node

def search_graph(request, prefix, bits, **kwargs):
    """Display a graph showing all RPKI objects which contribute toward the origin validation status of the given prefix"""
    rng = resource_range_ip.parse_str('%s/%s' % (prefix, bits))

    # for now only consider the most recent epoch
    epoch = models.Epoch.objects.all().order_by('-when').first()

    # locate any certs which cover this prefix
    certs = []
    roas = []
    crls = []
    gbrs = []
    mfts = []

    g = gv.digraph('RPKI')

    # use subgraphs to denote repositories
    # clusters must be named with the cluster_ prefix
    subgraph_map = {}

    def subgraph(uri):
        if uri is None:
            return g
        r = urlparse.urlparse(uri.uri)
        if r.hostname not in subgraph_map:
            name = 'cluster_%d' % (len(subgraph_map.keys()))
            subgraph_map[r.hostname] = gv.graph(g, name)
            gv.setv(subgraph_map[r.hostname], 'label', str(r.hostname))
            gv.setv(subgraph_map[r.hostname], 'color', 'blue')
        return subgraph_map[r.hostname]

    certs = models.ResourceCert.objects.filter(
            validation__epoch=epoch,
            addresses__version=rng.version,
            addresses__prefix_min__lte=rng.min,
            addresses__prefix_max__gte=rng.max)

    for cert in certs:
        # find this cert's parent (if any)
        # since querysets are cached, should be fine to reuse it here
        if cert.aki:
            parent = certs.get(ski=cert.aki)
            if hasattr(parent, 'node'):
                parent_node = parent.node
            else:
                parent_node = make_node(parent, 'cert', epoch, None, subgraph)
                parent.node = parent_node # decorate object
        else:
            parent_node = None

        if hasattr(cert, 'node'):
            cert_node = cert.node
        else:
            cert_node = make_node(cert, 'cert', epoch, parent_node, subgraph)
            cert.node = cert_node # decorate object

        # roas - subset that cover target prefix
        for roa in cert.get_roas(epoch).filter(
                prefixes__version=rng.version,
                prefixes__prefix_min__lte=rng.min,
                prefixes__prefix_max__gte=rng.max):
            make_node(roa, 'roa', epoch, cert_node, subgraph, shape='rectangle')
            roas.append(roa)

        # manifests
        for mft in cert.get_mfts(epoch):
            make_node(mft, 'mft', epoch, cert_node, subgraph, shape='rectangle')
            mfts.append(mft)

        # crls
        for crl in cert.get_crls(epoch):
            make_node(crl, 'crl', epoch, cert_node, subgraph, shape='rectangle')
            crls.append(crl)

        # ghostbusters
        for gbr in cert.get_gbrs(epoch):
            make_node(gbr, 'gbr', epoch, cert_node, subgraph, shape='rectangle')
            gbrs.append(gbr)

    svg = make_svg(g)

    return render(request, 'viz/browse.html', {'svg': svg, 'epoch': epoch, 'certs': certs, 'crls': crls, 'mfts': mfts, 'gbrs': gbrs, 'roas': roas})

# vim:sw=4 ts=8 expandtab
