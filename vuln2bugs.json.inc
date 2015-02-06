//This file is not pure json. It is in the hjson format (see hjson.org)
{
	//Connection settings to ElasticSearch
	"mozdef": {
		"host": "",
		"port": 9200,
		"proto": "http"
	},

	"bugzilla": {
		"host": "https://bugzilla-dev.allizom.org/rest/",
		"user": "",
		"pass": ""
	},

	//These teams need to exist (autogroup in mozdef)
	//Note that the opposite can also happen where teams get created in mozdef, but not configured here
	//Either way missing or extra teams will not get bugs assigned, of course.
	"teamsetup": {
		//Rather traditional example here
		"opsec": {
			"product": "mozilla.org",
			"component": "Security Assurance: Operations",
			"flags": ["group_mozilla-employee-confidential"],
			"status": "NEW",
			"priority": "P1",
			"severity": "major"
		}
	},

	//Filters, etc. settings
	"es": {
		"index": "vulnerabilities",
		"time_period": 24,
		//You can add any filter you want here as long as the value exists in MozDef
		//Because ES uses "must" "must not" and "should" instead of "and" and "or", you have to ensure your filter is very precise.
		//In particular if an item can have many values, make sure you negate the values that you never want to see.
		"filter": {
			"sourcename": "production",
			"vuln.status": "open",
			//CVSS filter, see http://en.wikipedia.org/wiki/CVSS if you're not familiar with it
			//These are examples to get you started
			"vuln.cvss_vector.access_complexity": ["low", "!medium", "!high"],			//high, medium, low
			"vuln.cvss_vector.access_vector": ["!local", "!adjacentnetwork", "network"],		//local, adjacent network, network
			"vuln.cvss_vector.authentication": ["none", "single", "!multiple"],			//none, single, multiple
			"vuln.cvss_vector.confidentiality_impact": ["!none", "partial", "complete"],		//none, partial, complete
			"vuln.cvss_vector.integrity_impact": ["!none", "partial", "complete"],			//none, partial, complete
			"vuln.cvss_vector.availability_impact": ["!none", "partial", "complete"],		//none, partial, complete
			"vuln.impact_label": ["!mediumlow", "high", "maximum"]					//mediumlow, high, maximum (OpSec Levels)
		}
	}
}
