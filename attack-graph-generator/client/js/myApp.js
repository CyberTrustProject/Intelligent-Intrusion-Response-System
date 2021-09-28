/**
*
* @licstart  The following is the entire license notice for the
*  JavaScript code in this page.
*
* This file is part of FIWARE CyberCAPTOR,
* instance of FIWARE Cyber Security Generic Enabler
* Copyright (C) 2012-2015  Thales Services S.A.S.,
* 20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE
*
* FIWARE CyberCAPTOR is free software; you can redistribute
* it and/or modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 3 of the License,
* or (at your option) any later version.
*
* FIWARE CyberCAPTOR is distributed in the hope
* that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
* warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with FIWARE CyberCAPTOR.
* If not, see <http://www.gnu.org/licenses/>.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this page.
*
*/


/**
*	Defines dependencies
*/
var myApp = angular.module('CyberCAPTOR', ['routeAppControllers', 'ngRoute', 'ngRadialGauge', 'myModule', 'angularFileUpload']);


/**
*	Defines constant
*/
myApp.constant("myConfig", {
	// URL base for REST request
    "url": "http://127.0.0.1:10000/cybercaptor-server/rest/json",
    "config" : "http://127.0.0.1:10000/cybercaptor-server/rest/json/configuration/remediation-cost-parameters"
});

/**
*	Defines route and controller
*/
myApp.config(['$routeProvider', '$httpProvider', function($routeProvider, $httpProvider) {

	$httpProvider.defaults.withCredentials = true;
	$httpProvider.defaults.useXDomain = true;

	$routeProvider
	.when('/welcome', {
		'controller': 'initController',
		'templateUrl': 'view/welcome.html'
	})
	.when('/configuration', {
		'controller': 'configurationController',
		'templateUrl': 'view/configuration.html'
	})
	.when('/attackGraph', {
		'controller': 'attackGraphController',
		'templateUrl': 'view/attackGraph.html'
	})
	.when('/attackPath', {
		'controller': 'attackPathController',
		'templateUrl': 'view/attackPath.html'
	})
	.when('/simulation', {
		'controller' : 'simulController',
		'templateUrl' : 'view/remediationsSimulation.html'
	})
	.when('/dynamicRiskAnalysis', {
		'controller' : 'dynamicRiskAnalysisController',
		'templateUrl' : 'view/dynamicRiskAnalysis.html'
	})
	.otherwise({
		redirectTo: '/attackGraph'
	});
}]);

var routeAppControllers = angular.module('routeAppControllers', []);
