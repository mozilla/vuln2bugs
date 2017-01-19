//This file is not pure json. It is in the hjson format (see hjson.org)
{
	//Connection settings to ElasticSearch
	"mozdef": {
		"host": "",
		"port": 9200,
		"proto": "http",
		"dashboard_url": ""
	},

	"bugzilla": {
		"host": "https://bugzilla-dev.allizom.org",
		"api_key": ""
	},

	//Link to include in bug pointing to documentation
	"doclink": "https://url/vulnerability_management/",

	//Set to link to include to service-map raw owners list
	"eisowners": "https://service-map/api/v1/owners",

	//These teams need to exist (asset.owner.v2bkey in mozdef event)
	//Note that the opposite can also happen where teams get created in mozdef, but not configured here
	//Either way missing or extra teams will not get bugs assigned, of course.
	"teamsetup": {
		"myteam": {
			"name": "nicerteamname",
			"filter": "most-critical-only",
			"product": "myproduct",
			"component": "mycomponent",
			"groups": [""],
			"status": "NEW",
			"priority": "P1",
			"version": "other",
			"severity": "major"
		}
	},

	//Filters, etc. settings
	"es": {
		"index": "vulnerabilities",
		// Here you can add filters to filter out vulnerabilities that do not match
		// the specified criteria for processing.
		//
		// Required:
		// _time_period: How far back to query (hours)
		// sourcename:   query for vulnerabilities with specified sourcename
		//
		// Optional:
		// mincvss: Vulnerabilities must have at least specified CVSS value, defaults
		//          to 0 if not specified.
		"default-filter": {
			"_time_period": 24,
			"mincvss": 5.0,
			"sourcename": "scanapi"
		},
		"all-vulnerabilities": {
			"_time_period": 24,
			"sourcename": "scanapi"
		}
	}
}
