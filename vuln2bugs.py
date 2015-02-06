#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright (c) 2015 Mozilla Corporation
# Author: Guillaume Destuynder <gdestuynder@mozilla.com>

# Sample MozDef vuln data format for reference.
#
#{'asset': {'assetid': 410,
#           'autogroup': 'opsec',
#           'hostname': 'orangefactor1.dmz.phx1.mozilla.com',
#           'ipv4address': '10.8.74.53',
#           'macaddress': '005056942621',
#           'os': 'Red Hat Enterprise Linux 6.3'},
# 'customendpoint': True,
# 'description': 'system vulnerability management automation',
# 'endpoint': 'vulnerability',
# 'sourcename': 'production',
# 'utctimestamp': '2015-02-05T17:15:09.559458+00:00',
# 'vuln': {'age_days': 47.8,
#          'cves': ['CVE-2014-0475', 'CVE-2014-5119'],
#          'cvss': 7.5,
#          'cvss_vector': {'access_complexity': 'low',
#                          'access_vector': 'network',
#                          'authentication': 'none',
#                          'availability_impact': 'partial',
#                          'confidentiality_impact': 'partial',
#                          'integrity_impact': 'partial'},
#          'discovery_time': 1423143725,
#          'impact_label': 'high',
#          'known_exploits': True,
#          'known_malware': False,
#          'patch_in': 7.0,
#          'proof': 'Vulnerable OS: Red Hat Enterprise Linux 6.3 * glibc - '
#                   'version 2.12-1.80.el6_3.6 is installed',
#          'status': 'open',
#          'title': 'RHSA-2014:1110: glibc security update',
#          'vulnid': 'nexpose:21523'}
#}

import pyes
import os
from pyes.es import ES
import pytz
from datetime import datetime
from dateutil.parser import parse
from datetime import timedelta
import bugsy
import hjson as json

def toUTC(suspectedDate, localTimeZone=None):
    '''Anything => UTC date. Magic.'''
    if (localTimeZone == None):
        localTimeZone = '/'.join(os.path.realpath('/etc/localtime').split('/')[-2:])
    utc = pytz.UTC
    objDate = None
    if (type(suspectedDate) == str):
        objDate = parse(suspectedDate, fuzzy=True)
    elif (type(suspectedDate) == datetime):
        objDate=suspectedDate

    if (objDate.tzinfo is None):
        objDate=pytz.timezone(localTimeZone).localize(objDate)
        objDate=utc.normalize(objDate)
    else:
        objDate=utc.normalize(objDate)
    if (objDate is not None):
        objDate=utc.normalize(objDate)

    return objDate

def get_all_entries(config):
    es = ES((config['mozdef']['proto'], config['mozdef']['host'], config['mozdef']['port']))

    # Filters
    begindateUTC = toUTC(datetime.now() - timedelta(hours=config['es']['time_period']))
    enddateUTC= toUTC(datetime.now())
    fDate = pyes.RangeQuery(qrange=pyes.ESRange('utctimestamp', from_value=begindateUTC, to_value=enddateUTC))

    # Load queries from our json config.
    # Lists are "should" unless an item is negated with "!" then it's must_not
    # Single items are "must"
    query = pyes.query.BoolQuery()
    for item in config['es']['filter']:
        val = config['es']['filter'][item]
        if (type(val) != list):
            if (val.startswith("!")):
                query.add_must_not(pyes.MatchQuery(item, val))
            else:
                query.add_must(pyes.MatchQuery(item, val))
        else:
            for v in val:
                if (v.startswith("!")):
                    query.add_must_not(pyes.MatchQuery(item, v[1:]))
                else:
                    query.add_should(pyes.MatchQuery(item, v))

    q = pyes.ConstantScoreQuery(query)
    q = pyes.FilteredQuery(q, pyes.BoolFilter(must=[fDate]))

    results = es.search(query=q, indices=config['es']['index'])

    raw = results._search_raw(0, results.count())
    es.force_bulk()

    if (raw._shards.failed != 0):
        raise Exception("Some shards failed! {0}".format(raw._shards.__str__()))

    # Nobody cares for the metadata past this point (all the goodies are in '_source')
    data = []
    for i in raw.hits.hits:
        data += [i._source]
    return data

def get_all_assets(vulns):
    '''Returns unique list of assets'''
    assets = dict()
    for i in vulns:
        assets[i.asset.assetid] = i.asset
    return assets

def get_all_groups(vulns):
    '''Returns unique list of groups/teams'''
    groups = list()
    for i in vulns:
        groups += [i.asset.autogroup]
    return list(set(groups))

def bug_create(asset, vuln):
    '''This will create a Bugzilla bug using whatever settings you have for a team in 'teamsetup' '''
    #bz = bugsy.Bugsy(config['bugzilla']['user'], config['bugzilla']['pass'], config['bugzilla']['host'])
    bug = bugsy.Bug()

    tpl_body = """{quickdesc}
Expected time to patch: {time_to_patch} days (discovered {discovered} days ago)

Risk: {risk}
Access vector: {access_vector}
Exploitable: {exploitable}
Known public exploit: {exploit_available}

Affected:
{affected}
"""

    if ((bool(vuln.known_exploits) == True) or (bool(vuln.known_malware) == True)):
        exploit_available_r = "Yes"
    else:
        exploit_available_r = "Unknown"

    bug.summary = vuln.title+' - '
    for i in vuln.cves:
        bug.summary += i+' '

    bug.add_comment(tpl_body.format(quickdesc   = vuln.title,
                        time_to_patch           = vuln.patch_in,
                        discovered              = vuln.age_days,
                        risk                    = vuln.impact_label.upper(),
                        access_vector           = vuln.cvss_vector.access_vector,
                        exploitable             = "",
                        exploit_available       = exploit_available_r,
                        affected                = vuln.proof)
                    )

def main():
    #vulns_per_asset[assetid] = [vuln, vuln, ...]
    vulns_per_asset = dict()
    #team_assets_with_vulns['opsec'] = [1223, 234. ...] (these are asset ids)
    team_assets_with_vulns = dict()
    #This one is perhaps the most useful:
    #vulns_per_team['opsec'][{asset: <asset-data>, 'vulns': <vulns-for-that-asset>}, ...]
    vulns_per_team = dict()

    with open('vuln2bugs.json') as fd:
        config = json.load(fd)

    # Note that the pyes library returns DotDicts which are addressable like mydict['hi'] an mydict.hi
    raw = get_all_entries(config)
    teams = get_all_groups(raw)
    assets = get_all_assets(raw)

    # Fill in vulns_per_asset
    for i in raw:
        try:
            vulns_per_asset[i.asset.assetid] += [i.vuln]
        except KeyError:
            vulns_per_asset[i.asset.assetid] = [i.vuln]

    # Fill in teams and their vulnerable assetids
    for team in teams:
        team_assets_with_vulns[team] = [x for x in vulns_per_asset if assets[x].autogroup == team]


    # Unroll previous findings and fill in vulns_per_team which is arguably our master table
    for team in teams:
        vulns_per_team[team] = list()
        for asset in team_assets_with_vulns[team]:
            vulns_per_team[team] += [(assets[asset], vulns_per_asset[asset])]

    import code
    code.interact(local=locals())

if __name__ == "__main__":
    main()
