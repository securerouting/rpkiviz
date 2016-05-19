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

__version__ = '$Id: urls.py 5496 2013-09-19 16:25:32Z melkins $'

from django.conf.urls import patterns, url
from viz.views import (CertDetailView, RoaDetailView,
		GhostbusterDetailView, search_view, global_summary, prefix_view,
                expire_view, browse, browse_cert, search_graph)

urlpatterns = [
    url(r'^search$', search_view, name='res-search'),
    url(r'^epoch/(?P<epoch>\d+)/cert/(?P<pk>[^/]+)$', CertDetailView.as_view(), name='cert-detail'),
    url(r'^epoch/(?P<epoch>\d+)/gbr/(?P<pk>[^/]+)$', GhostbusterDetailView.as_view(), name='gbr-detail'),
    url(r'^epoch/(?P<epoch>\d+)/roa/(?P<pk>[^/]+)$', RoaDetailView.as_view(), name='roa-detail'),
    url(r'^prefix/(?P<network>[.0-9]+)/(?P<mask>[.0-9]+)', prefix_view, name='prefix-view'),
    url(r'^$', global_summary, name='global-summary'),
    url(r'^expiring/$', expire_view),
    url(r'^browse/$', browse),
    url(r'^browse/epoch/(?P<epoch>\d+)/cert/(?P<pk>\d+)/$', browse_cert, name='browse-cert-epoch'),
    url(r'^cert/(?P<pk>\d+)/$', browse_cert, name='browse-cert'),
    url(r'^graph/(?P<prefix>[0-9a-f:.]+)/(?P<bits>\d+)/?$', search_graph, name='prefix-graph')
]

# vim:sw=4 ts=8 expandtab
