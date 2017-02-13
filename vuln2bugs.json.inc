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

	// Can be defined to create a bug indicating any vulnerabilities filtered for
	// various team configurations. If this is omitted, no filter report will be
	// created. If present, any teams you wish to include in the filter report must
	// have "reportfiltered" set to true in their configuration.
	//
	// if an exceptions file is present, this file can include a list of vulnerability
	// names tha will never be filtered. In this file, comments are permitted with # and
	// each line should be <teamname> <regexp>. teamname can be * to apply globally.
	"filteredreport": {
		// Must be configured to run on a specific day, 0 == Mon ... 6 == Sun
		"weeklyrun": 0,
		"product": "myproduct",
		"component": "mycomponent",
		"groups": [""],
		"status": "NEW",
		"priority": "P1",
		"version": "other",
		"severity": "major",
		"exceptions": "/path/to/exceptions/file.txt"
	},

	//These teams need to exist (asset.owner.v2bkey in mozdef event)
	//Note that the opposite can also happen where teams get created in mozdef, but not configured here
	//Either way missing or extra teams will not get bugs assigned, of course.
	"teamsetup": {
		"myteam": {
			"name": "nicerteamname",
			"filter": "most-critical-only",
			// reportfiltered is optional, if set to true any filter report bugs created
			// will include details for this team
			"reportfiltered": false,
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
		// risklabels: The risk label in the vulnerability must be set to a value in
		//             risklabels to be escalated
		"default-filter": {
			"_time_period": 24,
			"mincvss": 5.0,
			"risklabels": ["high", "critical"],
			"sourcename": "scanapi"
		},
		"all-vulnerabilities": {
			"_time_period": 24,
			"sourcename": "scanapi"
		}
	}
}
