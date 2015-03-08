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
#           'operator': 'none',
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
import sys, os
from pyes.es import ES
import pytz
from datetime import datetime
from dateutil.parser import parse
from datetime import timedelta
import bugsy
import hjson as json
from io import StringIO
from collections import Counter

DEBUG = True

def debug(msg):
    if DEBUG:
        sys.stderr.write('+++ {}\n'.format(msg))

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

def get_entries(config, team):
    teamfilter = config['teamsetup'][team]['filter']
    es = ES((config['mozdef']['proto'], config['mozdef']['host'], config['mozdef']['port']))

    # Default filter - time period
    try:
        td = config['es'][teamfilter]['_time_period']
    except KeyError:
        debug('No _time_period defined, defaulting to 24h')
        td = 24
    begindateUTC = toUTC(datetime.now() - timedelta(hours=td))
    enddateUTC= toUTC(datetime.now())
    fDate = pyes.RangeQuery(qrange=pyes.ESRange('utctimestamp', from_value=begindateUTC, to_value=enddateUTC))
    # Default filter - operator
    try:
        operator = config['teamsetup']['operator']
    except KeyError:
        debug('No operator defined, defaulting to any')
        operator = None

    # Load team queries from our json config.
    # Lists are "should" unless an item is negated with "!" then it's must_not
    # Single items are "must"
    query = pyes.query.BoolQuery()
    for item in config['es'][teamfilter]:
        # items starting with '_' are internal/reserved, like _time_period
        if (item.startswith('_')):
            continue
        val = config['es'][teamfilter][item]
        if (type(val) == str):
            if (val.startswith("!")):
                query.add_must_not(pyes.MatchQuery(item, val))
            else:
                query.add_must(pyes.MatchQuery(item, val))
        elif (type(val) == list):
            for v in val:
                if (v.startswith("!")):
                    query.add_must_not(pyes.MatchQuery(item, v[1:]))
                else:
                    query.add_should(pyes.MatchQuery(item, v))

    q = pyes.ConstantScoreQuery(query)
    q = pyes.FilteredQuery(q, pyes.BoolFilter(must=[fDate]))

    results = es.search(query=q, indices=config['es']['index'])

    raw = results._search_raw(0, results.count())
    # This doesn't do much, but pyes has no "close()" or similar functionality.
    es.force_bulk()

    if (raw._shards.failed != 0):
        raise Exception("Some shards failed! {0}".format(raw._shards.__str__()))

    # Nobody cares for the metadata past this point (all the goodies are in '_source')
    data = []
    for i in raw.hits.hits:
        data += [i._source]
    return data

def get_assets(vulns):
    '''Returns unique list of assets from a vuln list'''
    assets = dict()

    for i in vulns:
        assets[i.asset.assetid] = i.asset

    return assets

def get_groups(vulns):
    '''Returns unique list of groups/teams from a vuln list'''
    groups = list()
    for i in vulns:
        groups += [i.asset.autogroup]

    return list(set(groups))

def get_vulns_get_asset(raw):
    '''Returns a dict-struct like this:
    vulns_per_asset[assetid] = [vuln, vuln, ...]
    '''
    vulns_per_asset = dict()

    for i in raw:
        try:
            vulns_per_asset[i.asset.assetid] += [i.vuln]
        except KeyError:
            vulns_per_asset[i.asset.assetid] = [i.vuln]

    return vulns_per_asset

def get_team_assets_with_vulns(raw, vulns_per_asset, assets):
    '''Returns a dict-struct like this:
    team_assets_with_vulns['opsec'] = [1223, 234. ...] (these are asset ids)
    Not necessary if your raw result set is already filtered on the team.

    If you use this, you probably also will want this:
    # Unroll previous findings and fill in vulns_per_team which is arguably our master table
    # vulns_per_team['opsec'][{asset: <asset-data>, 'vulns': <vulns-for-that-asset>}, ...]
    #
    # vulns_per_team = dict()
    #
    #    for team in teams:
    #        vulns_per_team[team] = list()
    #        for asset in team_assets_with_vulns[team]:
    #            vulns_per_team[team] += [(assets[asset], vulns_per_asset[asset])]
    '''
    team_assets_with_vulns = dict()
    team_assets_with_vulns[team] = [x for x in vulns_per_asset if assets[x].autogroup == team]

    return team_assets_with_vulns

def bug_create(config, teamcfg, title, body, attachments):
    '''This will create a Bugzilla bug using whatever settings you have for a team in 'teamsetup' '''
    bzurl = config['bugzilla']['host'].strip('/')
    bz = bugsy.Bugsy(username=config['bugzilla']['user'],
                     password=config['bugzilla']['pass'],
                     bugzilla_url=bzurl+'/rest')
    bug = bugsy.Bug()
    bug.component = teamcfg['component']
    bug.product = teamcfg['product']
    bug.version = teamcfg['version']
    bug.summary = title
    bug.add_comment(body)
    bz.put(bug)
    bug.status = teamcfg['status']
    bug.update()
    create_attachment(bz.session, bzurl, bug, 'hostnames_only.txt', 'List of affected hostnames and their IPs',
                    attachments[1])
    create_attachment(bz.session, bzurl, bug, 'full_details.txt',
                    'Complete details including CVEs, OS, etc. per hostname.', attachments[0])
    debug('Created bug {}/{}'.format(bzurl, bug.id))

def create_attachment(session, bzurl, bug, filename, description, attachment):
    # The bugzilla API doesn't support much. Like attachments.
    # So we're just hacking around here really.
    """
    session is python requests session (normally bz.session)
    bzurl is the bugzilla base URL (not REST)
    bug is a Bugsy bug to add the attachment to
    filename is a filename of your choice, will appear as attached filename
    description is the attachment description
    attachment is a string, the attachement itsef. Will appear as text/plain file.
    """
    r = session.get('{}/attachment.cgi?bugid={}&action=enter'.format(bzurl, bug.id))
    # Find the CSRF token. As dirty as it gets. This is hardcoded for simplicity.
    # If things change, look at the page source to find it.
    try:
        pos = r.text.find('name="token"')
        token = r.text[pos:pos+100].split('\n')[0]
        token = token.split('"')[3]
    except IndexError:
        debug("Finding the attachment token has failed. Damn.")
        return

    # The attachement POST request has to look like this. The token is the one taken from the previous page, not the
    # cookie token.
    post_data = {'bugid': str(bug.id),
            'action': 'insert',
            'token': token,
            'description': description,
            'contenttypemethod': 'manual',
            'contenttypeselection': 'text/plain',
            'contenttypeentry': 'text/plain',
            'flag_type-4': 'X',
            'requestee_type-4': '',
            'flag_type-607': 'X',
            'requestee_type-607': '',
            'flag_type-481': 'X',
            'bug_status': bug.status,
            'comment': '',
            'needinfo_role': 'other',
            'needinfo_from': ''}
    file_data = {'data': (filename, StringIO(attachment))}
    r = session.post(bzurl+'/attachment.cgi', data=post_data, files=file_data)
    return r

def parse_proof(proof):
    '''Finds a package name, os, etc. in a proof-style string, such as:
    Vulnerable OS: Red Hat Enterprise Linux 5.5 * krb5-libs - version 1.6.1-55.el5_6.1 is installed

    Returns a dict = {'pkg': 'package name', 'os': 'os name', 'version': 'installed version'}
    or None if parsing failed.
    '''

    osname = ''
    pkg = ''
    version = ''

    try:
        tmp = proof.split('Vulnerable OS: ')[1]
        tmp = tmp.split('*')
        osname = tmp[0].strip()
        tmp = tmp[1].split('-')
        pkg = tmp[0].lstrip().strip()
        tmp = str.join('', tmp[1:]).split('version ')[1]
        version = tmp.split(' is installed')[0]
    except IndexError:
        return None

    return {'pkg': pkg, 'os': osname, 'version': version}

def process_vuln_flatmode(teamcfg, assets, vulns):
    '''Outputs a short, flat-ish text list of vulnerabilities per asset/system for use in attachments, text body, etc.'''
    textdata = ''
    hostnames = ''
    pkg_affected = dict()

    # Unroll all vulns
    for a in assets:
        risks = list()
        proofs = list()
        titles = list()
        ages = list()
        patch_in = list()
        cves = list()
        for v in vulns[a]:
            risks       += [v.impact_label.upper()]
            proofs      += [v.proof]
            titles      += [v.title]
            ages        += [v.age_days]
            cves        += v.cves
            patch_in    += [v.patch_in]

        #pkg_vuln = Counter(proofs).most_common()
        pkgs = list()
        pkg_parsed = True
        pkg_ver = dict()
        for i in proofs:
            p = parse_proof(i)
            pname = p['pkg']
            pver = p['version']
            if p == None:
                pkg_parsed = False
                pkgs += [i]
                pkg_affected[i] = 'Unknown'
            else:
                pkg_ver[pname] = pver
                pkgs += [pname]
                try:
                    pkg_affected[pname] += [pver]
                    pkg_affected[pname] = list(set(pkg_affected[pname]))
                except KeyError:
                    pkg_affected[pname] = [pver]

        # Uniquify
        pkgs    = list(set(pkgs))
        risks   = list(set(risks))
        cves    = list(set(cves))

        if pkg_parsed:
            pkgs_pretty = list()
            for i in pkgs:
                pkgs_pretty += ['{} (affected version {})'.format(i, pkg_ver[i])]
        else:
            pkgs_pretty = pkgs

        # What's the oldest vuln found?
        oldest = 0

        for i in ages:
            if i > oldest:
                oldest = i

        data = """[{nr_vulns}] {hostname} {ipv4}: Risk: {risk} - oldest vulnerability has been seen {age} day(s) ago.
Affected by CVES: {cve}.
Affected OS: {osname}
Packages to upgrade: {packages}
""".format(hostname     = assets[a].hostname,
            ipv4        = assets[a].ipv4address,
            nr_vulns    = len(vulns[a]),
            risk        = str.join(',', risks),
            age         = oldest,
            cve         = str.join(',', cves),
            osname      = assets[a].os,
            packages    = str.join(',', pkgs_pretty))

        hostnames += "{ip} {hostname}\n".format(hostname=assets[a].hostname, ip=assets[a].ipv4address)
        textdata += data

    return (textdata, hostnames, pkg_affected)

def main():
    debug('Debug mode on')

    with open('vuln2bugs.json') as fd:
        config = json.load(fd)

    teams = config['teamsetup']

    # Note that the pyes library returns DotDicts which are addressable like mydict['hi'] an mydict.hi
    for team in teams:
        debug('Processing team: {} using filter {}'.format(team, teams[team]['filter']))
        raw = get_entries(config, team)
        assets = get_assets(raw)
        vulns_per_asset = get_vulns_get_asset(raw)
        debug('{} assets affected by vulnerabilities with the selected filter.'.format(len(assets)))
        (attachment_text, attachment_hostnames, pkgs_affected) = process_vuln_flatmode(teams[team], assets, vulns_per_asset)

        bug_body = "{} hosts affected by filter {}\n\n".format(len(assets), teams[team]['filter'])
        bug_body += "({}) Packages affected:\n".format(len(pkgs_affected))
        for i in pkgs_affected:
            bug_body += "{name}: {version}\n".format(name=i, version=','.join(pkgs_affected[i]))

        bug_create(config, teams[team], "[{} hosts] Bulk vulnerability report for {} using filter: {}".format(
                    len(assets), team, teams[team]['filter']), bug_body, [attachment_text,
                        attachment_hostnames])

if __name__ == "__main__":
    main()
