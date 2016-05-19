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

from django import forms

from rpki.resource_set import resource_range_ip
from rpki.exceptions import BadIPResource
from rpki.POW import POWError

class SearchForm(forms.Form):
    resource = forms.CharField(required=True)

    def clean_resource(self):
	try:
	    rng = resource_range_ip.parse_str(self.cleaned_data.get('resource'))
	    return rng
	except BadIPResource:
	    raise forms.ValidationError('invalid prefix')
        except POWError:
	    raise forms.ValidationError('invalid prefix')

# vim:sw=4 expandtab
