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
import hjson as json
from io import StringIO
from collections import Counter
import socket

from bugzilla import *

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

def bug_create(config, teamcfg, title, body, attachments):
    '''This will create a Bugzilla bug using whatever settings you have for a team in 'teamsetup' '''
    url = config['bugzilla']['host']
    b = bugzilla.Bugzilla(url=url+'/rest/', api_key=config['bugzilla']['api_key'])

    bug = bugzilla.DotDict()
    bug.component = teamcfg['component']
    bug.product = teamcfg['product']
    bug.version = teamcfg['version']
    bug.status = teamcfg['status']
    bug.summary = title
    bug.groups = teamcfg['groups']
    bug.description = body
    bug.whiteboard = 'autoentry v2b-autoclose=yes v2b-autoremind=yes'
    bug = b.post_bug(bug)

    for i in attachments:
        b.post_attachment(bug.id, i)

    debug('Created bug {}/{}'.format(url, bug.id))

class VulnProcessor():
    '''The VulnProcessor takes a teamvuln object and extra prettyfi-ed data as strings, lists, etc'''
    def __init__(self, config, teamvulns):
        self.teamvulns = teamvulns
        self.config = config
        a, b, c = self.process_vuln_flatmode(config, teamvulns.assets, teamvulns.vulnerabilities_per_asset)
        self.full_text_output = a
        self.short_csv = b
        self.affected_packages_list = c

    def summarize(self, data, dlen=64):
        '''summarize any string longer than dlen to dlen+ (truncated)'''
        if len(data) > dlen:
            return data[:dlen]+' (truncated)'
        return data

    def get_full_text_output(self):
        return self.full_text_output

    def get_short_csv(self):
        return self.short_csv

    def get_affected_packages_list(self):
        return self.affected_packages_list

    def process_vuln_flatmode(self, teamcfg, assets, vulns):
        '''Preparser that could use some refactoring.'''
        textdata = ''
        short_list = ''
        pkg_affected = dict()

        # Unroll all vulns
        for a in assets:
            risks = list()
            proofs = list()
            titles = list()
            ages = list()
            patch_in = list()
            cves = list()
            for v in vulns[a.id]:
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
                p = self.parse_proof(i)
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
                    pkgs_pretty += ['{} (affected version {})'.format(i, self.summarize(pkg_ver[i]))]
            else:
                pkgs_pretty = pkgs

            # What's the oldest vuln found?
            oldest = 0

            for i in ages:
                if i > oldest:
                    oldest = i

            data = """{nr_vulns} vulnerabilities for {hostname} {ipv4}

    Risk: {risk} - oldest vulnerability has been seen {age} day(s) ago.
    CVES: {cve}.
    OS: {osname}
    Packages to upgrade: {packages}
    -------------------------------------------------------------------------------------

    """.format(hostname     = a.hostname,
                ipv4        = a.ipv4address,
                nr_vulns    = len(vulns[a.id]),
                risk        = str.join(',', risks),
                age         = oldest,
                cve         = self.summarize(str.join(',', cves)),
                osname      = a.os,
                packages    = str.join(',', pkgs_pretty))

            short_list += "{hostname},{ip},{pkg}\n".format(hostname=a.hostname, ip=a.ipv4address, pkg=str.join(' ', pkgs))
            textdata += data

        return (textdata, short_list, pkg_affected)

    def parse_proof(self, proof):
        '''Finds a package name, os, etc. in a proof-style (nexpose) string, such as:
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

class TeamVulns():
    '''TeamVulns extract the vulnerability data from MozDef and sorts it into clear structures'''
    def __init__(self, config, team):
        self.team = team
        self.config = config
        # Get all entries/data from ES/MozDef
        self.raw = self.get_entries()
        # Sort out assets
        self.assets = self.get_assets()
        # Sort out vulnerabilities
        self.vulnerabilities_per_asset = self.get_vulns_per_asset()

    def get_vulns_per_asset(self):
        '''Returns a dict-struct like this:
        vulns_per_asset[assetid] = [vuln, vuln, ...]
        '''
        vulns_per_asset = dict()

        for i in self.raw:
            try:
                vulns_per_asset[i.asset.assetid] += [i.vuln]
            except KeyError:
                vulns_per_asset[i.asset.assetid] = [i.vuln]

        return vulns_per_asset

    def get_assets(self):
        '''Returns unique list of assets from a vuln list'''
        # For sorting until we get priorities, we use a list instead of a dict
        # Then deal with the inconveniences ;)
        assets = list()

        for i in self.raw:
            i.asset['id'] = i.asset.assetid
            assets += [i.asset]

        assets = sorted(assets, key=lambda item: socket.inet_aton(item['ipv4address']))
        assets.reverse()

        return assets

    def get_entries(self):
        '''Get all entries for a team + their filter from ES/MozDef'''
        teamfilter = self.config['teamsetup'][self.team]['filter']
        es = ES((self.config['mozdef']['proto'], self.config['mozdef']['host'], self.config['mozdef']['port']))

        # Default filter - time period
        try:
            td = self.config['es'][teamfilter]['_time_period']
        except KeyError:
            debug('No _time_period defined, defaulting to 24h')
            td = 24
        begindateUTC = toUTC(datetime.now() - timedelta(hours=td))
        enddateUTC= toUTC(datetime.now())
        fDate = pyes.RangeQuery(qrange=pyes.ESRange('utctimestamp', from_value=begindateUTC, to_value=enddateUTC))
        # Default filter - operator
        try:
            operator = self.config['teamsetup'][self.team]['operator']
        except KeyError:
            debug('No operator defined, defaulting to any')
            operator = None

        # Load team queries from our json config.
        # Lists are "should" unless an item is negated with "!" then it's must_not
        # Single items are "must"
        query = pyes.query.BoolQuery()
        query.add_must(pyes.MatchQuery('asset.autogroup', self.team))
        if operator != None:
            query.add_should(pyes.MatchQuery('asset.operator', operator))
        query.add_should(pyes.MatchQuery('asset.operator', 'unknown'))
        for item in self.config['es'][teamfilter]:
            # items starting with '_' are internal/reserved, like _time_period
            if (item.startswith('_')):
                continue
            val = self.config['es'][teamfilter][item]
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

        results = es.search(query=q, indices=self.config['es']['index'])

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


def create_bug_type_flat(config, team, teamvulns, processor):
    teamcfg = config['teamsetup'][team]

    full_text = processor.get_full_text_output()
    short_csv = processor.get_short_csv()
    pkgs = processor.get_affected_packages_list()

    # Attachments
    ba = [bugzilla.DotDict(), bugzilla.DotDict()]
    ba[0].file_name = 'short_list.csv'
    ba[0].summary = 'CSV list of affected ip,hostname,package(s)'
    ba[0].data = short_csv
    ba[1].file_name = 'detailled_list.txt'
    ba[1].summary = 'Details including CVEs, OS, etc. affected'
    ba[1].data = full_text

    bug_body = "{} hosts affected by filter {}\n\n".format(len(teamvulns.assets), teamcfg['filter'])
    bug_body += "({}) Packages affected:\n".format(len(pkgs))
    for i in pkgs:
        bug_body += "{name}: {version}\n".format(name=i, version=','.join(pkgs[i]))
    bug_body += "\n\nFor additional details, queries, graphs, etc. see also {}".format(config['mozdef']['dashboard_url'])

    bug_create(config, teamcfg, title="[{} hosts] Bulk vulnerability report for {} using filter: {}".format(
                len(teamvulns.assets), team, teamcfg['filter']), body=bug_body, attachments=ba)

def main():
    debug('Debug mode on')

    with open('vuln2bugs.json') as fd:
        config = json.load(fd)

    teams = config['teamsetup']

    # Note that the pyes library returns DotDicts which are addressable like mydict['hi'] an mydict.hi
    for team in teams:
        debug('Processing team: {} using filter {}'.format(team, teams[team]['filter']))
        teamvulns = TeamVulns(config, team)
        processor = VulnProcessor(config, teamvulns)
        debug('{} assets affected by vulnerabilities with the selected filter.'.format(len(teamvulns.assets)))
        create_bug_type_flat(config, team, teamvulns, processor)

if __name__ == "__main__":
    main()
