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
*   Attack Path Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve attack path from server whit GET request.
*   Attack path is an object with Nodes and Links.
*   Can exist several attack path, so, it's necessary
*       to retrieve the ID of attack path.
*/
routeAppControllers.controller('attackPathController', function ($scope, $http, myConfig, serviceTest) {

    var defaultPath = {
        ID : 0,
        Value : 1
    };

    // Defautl view : logical
    $scope.view = {
        status : "Logical"
    };
    $scope.valueGauge = 0;

    // Function available in $scope, to begin the procedure
    $scope.init = function(){

        // Request the list of host : name, metric,...
        $http.get(myConfig.url + "/host/list")
            .then(function(host){
                $scope.listHosts = host.data;
            }, function(){alert("Loading of host list failed.")});

        // Request the number of path
        var number = $http.get(myConfig.url + "/attack_path/number")
            .then(function(valNumber) {
                $scope.items = valNumber.data;

                // Array of value for the list
                $scope.tab = [];

                // Fill the tab with ID and Values
                for(var i=1; i <= $scope.items.number; ++i){
                    $scope.tab[i-1] = {"ID" : i-1, "Value" : i};
                }

                // Request data to build graph
                var graph = $http.get(myConfig.url + "/attack_graph")
                    .then(function(valGraph) {

                        $scope.attack_graph = transformGraph(valGraph.data);

                        $scope.valSelecter = $scope.tab[defaultPath.ID];
                        $scope.appel(defaultPath);
                    }, function(){alert("Loading of attack graph failed.")})
            }, function(){alert("Loading of attack paths failed.")})
    };

    // Request to display data from remediation
    $scope.appel = function(numb){

        $http.get(myConfig.url + "/attack_path/" + numb.ID)
            .then(function(graph){
                var pathGraph = transformPath(graph.data, $scope.attack_graph);
                $scope.graphes = pathGraph;

                // Request to retrieve remediations for the attack path
                $http.get(myConfig.url + "/attack_path/" + numb.ID + "/remediations")
                    .then(function(dataRemediations){
                        $scope.dataRemediations = transformRemediation(dataRemediations.data);

                        // Limits attack path's score
                        if(pathGraph.scoring != undefined){
                            $scope.valueGauge = pathGraph.scoring * 100;
                        }
                    }, function(){alert("Loading of remediations failed.")})
            }, function(){alert("Loading of attack path" + numb.ID + " failed.")})
    };

    $scope.simulRemed = function(remed, path){

        serviceTest.setArray(remed, path);

        $http.get(myConfig.url + "/attack_path/" + path.ID + "/remediation/" + remed.ID)
            .then(function(graph){
                $scope.graphes = transformGraph(graph.data);

                serviceTest.set($scope.graphes);
            }, function(){alert("Loading of a remediation failed.")})
    }
});

// ****************************************************

/**
*   Gauge Controller
*   @param $scope
*
*   Initialize data from gauge
*/
routeAppControllers.controller("RadialGaugeDemoCtrl", function($scope){

    $scope.value = $scope.valueGauge;
    $scope.upperLimit = 100;
    $scope.lowerLimit = 0;
    $scope.unit = "";
    $scope.precision = 1;
    $scope.ranges = [
        {min: 0, max: 20, color: '#008000'},
        {min: 20, max: 40, color: '#FFFF00'},
        {min: 40, max: 60, color: '#FFA500'},
        {min: 60, max: 80, color: '#FF0000'},
        {min: 80, max: 100, color: '#000000'}
    ];
});


// ****************************************************

/**
*   Attack Graph Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve data from server
*/
routeAppControllers.controller('attackGraphController', function ($scope, $http, myConfig) {

    $scope.view = {
        status : "Logical"
    };

    $scope.init = function(){

        $http.get(myConfig.url + "/attack_path/number")
            .then(function(valNumber) {
                $scope.items = valNumber.data;

                var list = $http.get(myConfig.url + "/attack_path/list")
                    .then(function(valList) {
                        $scope.tab = valList.data;
                    }, function(){alert("Loading of attach path list failed.")});

                var graph = $http.get(myConfig.url + "/attack_graph")
                    .then(function(valGraph) {
                        $scope.graphes = transformGraph(valGraph.data);
                    }, function(){alert("Loading of attach graph failed.")})
            }, function(){alert("Loading of number of attack paths failed.")})
    };
});


// ****************************************************

/**
*   Simulation Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve data from server for remediation simulation
*/
routeAppControllers.controller('simulController', function ($scope, $http, myConfig, serviceTest) {

    $scope.view = {
        status : "Logical"
    };

    $scope.init = function(){

        var number = $http.get(myConfig.url + "/attack_path/number")
            .then(function(valNumber) {
                $scope.items = valNumber.data;

                var list = $http.get(myConfig.url + "/attack_path/list")
                    .then(function(valList) {
                         $scope.tab = valList.data;
                    }, function(){alert("Loading of attack path list failed.")});

                var graph = $http.get(myConfig.url + "/attack_graph")
                    .then(function(valGraph) {
                        var donnee = transformGraph(valGraph.data);
                        $scope.basicGraphes = donnee;

                        var graphTst = serviceTest.get();

                        $scope.graphes = transformRemediationSimulation(donnee, graphTst);
                    }, function(){alert("Loading of attach graph failed.")})
            }, function(){alert("Loading of number of attack paths failed.")})
    };

    $scope.validate = function(){

        var array = serviceTest.getArray();

        alert("Remediation validate");

         var validation = $http.get(myConfig.url + "/attack_path/" + array[1].ID + "/remediation/" + array[0].ID + "/validate")
            .then(function(){
            }, function(){alert("Sending remediation validation message failed.")})
    };
});


// ****************************************************

/**
*   Attack Graph Topological Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve data from server
*/
routeAppControllers.controller('attackGraphTopologicalController', function ($scope, $http, myConfig) {

    $scope.init = function(){

        var topological = $http.get(myConfig.url + "/attack_graph/topological")
            .then(function(data) {
                $scope.graphes = transformGraphTopo(data.data);
            }, function(){alert("Loading of topological attack graph failed.")})
    };
});


// ****************************************************

/**
*   Attack Path Topological Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve data from server
*/
routeAppControllers.controller('attackPathTopologicalController', function ($scope, $http, myConfig) {

    $scope.view = {
        status : "Logical"
    };

    $scope.init = function(){

        var number = $http.get(myConfig.url + "/attack_path/number")
            .then(function(valNumber){
                var numberPath = valNumber.data;

                // Array of value for the list
                $scope.tab = [];

                // Fill the tab with ID and Values
                for(var i=1; i <= numberPath.number; ++i){
                    $scope.tab[i-1] = {"ID" : i-1, "Value" : i};
                }

                $http.get(myConfig.url + "/attack_graph")
                    .then(function(attackGraph){
                        $scope.attack_graph = transformGraph(attackGraph.data);

                        var defaultPath = 0;

                        var topological = $http.get(myConfig.url + "/attack_path/" + defaultPath + "/topological")
                            .then(function(data) {
                                $scope.callTopoGraph($scope.valSelecter.ID);

                                // Default value in selecter
                                $scope.valSelecter = $scope.tab[0];
                            }, function(){alert("Loading of default topological attack path failed.")})
                    }, function(){alert("Loading of attack graph failed.")})
            }, function(){alert("Loading number of attack paths failed.")})
    };

    $scope.callTopoGraph = function(value){
        $http.get(myConfig.url + "/attack_path/" + value + "/topological")
            .then(function(graphTopo){
                $scope.graphes = transformPathTopo(graphTopo.data, $scope.attack_graph);
            }, function(){alert("Loading of a topological attack path failed.")})
    }
});

// ****************************************************
/**
*   Configuration Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*   Retrieve data from server
*   Initialize values
*/
routeAppControllers.controller('configurationController', function ($scope, $http, myConfig, serviceTest) {

    var values = ["Negligible", "Minor", "Normal", "Severe", "Catastrophic"];

    var i;
    $scope.choice = {
        status : 'global'
    };

    $scope.tabMetric = [];

    for(i=0; i < values.length; ++i){
        var value = values[i];
        $scope.tabMetric[i] = {"ID": i, "Value":value};
    }

    // Function available in $scope, to begin the procedure
    $scope.init = function(){

        // Request the list of host : name, metric,...
        $http.get(myConfig.url + "/host/list")
            .then(function(host){

		for(i=0; i<host.data.hosts.length; i++){
			if(host.data.hosts[i].security_requirements[0] == null ){
				host.data.hosts.splice(i);
			}
		}
                $scope.listHosts = host.data;

                    // Array of values before update
                    $scope.tabTmp = [];

                    var lengthHost = $scope.listHosts.hosts.length;

                    for(i=0; i<lengthHost; ++i){
                        $scope.listHosts.hosts[i].index = i;

                    }

                    for(i=0; i<lengthHost-1; ++i){
                        if($scope.listHosts.hosts[i].security_requirements[0] == undefined){
                            $scope.listHosts.hosts[i].security_requirements.push({"metric": "Negligible"});
                            $scope.tabTmp[i] = {"Value": $scope.listHosts.hosts[i].security_requirements[0].metric};

                        }
                        else{
                            // lengthHost-1 : remove "internet_Host" with undefined metric
                            for(i=0; i < lengthHost-1; ++i){
                                $scope.tabTmp[i] = {"Value": $scope.listHosts.hosts[i].security_requirements[0].metric};
                            }
                        }
                    }
            }, function(){alert("Loading of host list failed.")});


        $http.get(myConfig.config + "/firewall-rule")
            .then(function(data){

		$scope.firewall = data.data;

		$scope.firewall.operational_cost_parameters.restartCost;
		$scope.firewall.operational_cost_parameters.deploymentDuration;
		$scope.firewall.operational_cost_parameters.maintenanceDuration;
		delete $scope.firewall.operational_cost_parameters.remediationUninstallDuration;
		delete $scope.firewall.operational_cost_parameters.skillRateDeployment;
		delete $scope.firewall.operational_cost_parameters.skillRateMaintenance;
		delete $scope.firewall.operational_cost_parameters.skillRateTests;
		delete $scope.firewall.operational_cost_parameters.storageCost;
		delete $scope.firewall.operational_cost_parameters.usedPower;
		delete $scope.firewall.operational_cost_parameters.usedStorage;
		delete $scope.firewall.operational_cost_parameters.workCost;
		delete $scope.firewall.operational_cost_parameters.restartDuration;

		console.log($scope.firewall);

	}, function(){alert("Loading of firewall rule failed.")});
        $http.get(myConfig.config + "/patch")
            .then(function(data){

                $scope.patch = data.data;

		$scope.patch.operational_cost_parameters.restartCost;
		$scope.patch.operational_cost_parameters.deploymentDuration;
		$scope.patch.operational_cost_parameters.maintenanceDuration;
		delete $scope.patch.operational_cost_parameters.remediationUninstallDuration;
		delete $scope.patch.operational_cost_parameters.skillRateDeployment;
		delete $scope.patch.operational_cost_parameters.skillRateMaintenance;
		delete $scope.patch.operational_cost_parameters.skillRateTests;
		delete $scope.patch.operational_cost_parameters.storageCost;
		delete $scope.patch.operational_cost_parameters.usedPower;
		delete $scope.patch.operational_cost_parameters.usedStorage;
		delete $scope.patch.operational_cost_parameters.workCost;
		delete $scope.patch.operational_cost_parameters.restartDuration;

        }, function(){alert("Loading of patch data failed.")});

        serviceTest.set($scope);
        serviceTest.get();
    };

    $scope.updateValue = function(data, key){
        $scope.listHosts.hosts[key].security_requirements[0].metric = data.Value;
    };

    $scope.sendListHost = function(){
        var sendListHost = $http.post(myConfig.url + "/host/list", $scope.listHosts)
            .then(function(data){
                alert("Data Sent");
        }, function(){alert("Saving of host list failed.")})
    };

    $scope.sendForm = function(titleForm){
        var tmp = titleForm;
        var sendForm = $http.post(myConfig.url + "/configuration/remediation-cost-parameters/" + titleForm, $scope[titleForm])
            .then(function(data){
            }, function(){alert("Uploading remediation cost parameters failed.")})
    };
});


// ****************************************************
/**
*   Dynamic Risk Analysis Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*/

routeAppControllers.controller('dynamicRiskAnalysisController', function($scope, $http, myConfig){

    var diffTime = 0;
    var res = 0;
    var tab = [];
    $scope.tabAlert = { tab: tab };

    $scope.init = function(){

        var topological = $http.get(myConfig.url + "/attack_graph/topological")
            .then(function(data) {
                $scope.tmpData = data.data;
                $scope.graphes = transformGraphTopoDRA(data.data);
            }, function(){alert("Loading of topological attack graph failed.")})
    };


    function getAlarm(){
        var alarms = $http.get(myConfig.url + "/idmef/alerts")
            .then(function(info){
		        var data = info.data;
                // Stock data
                tab.unshift(data);

                var time = Date.now();

                if(data.alerts[0] != undefined){
                    // Convert timestamp
                    diffTime = time - data.alerts[0].timestamp;
                    res = transformTime(diffTime);
                    $scope.res = res;
                    data.alerts[0].res = res;
                }
            }, function(){alert("Loading of alerts failed.")})
    }

    $scope.alertFunc = function(){
        setInterval(getAlarm, 3000);
    };

    $scope.dra = function(data){

        $scope.graphes = transformGraphTopoDRA($scope.tmpData, data);

        $scope.draRemed = data.dynamic_remediations;
    };

    $scope.displayModal = function(){
        $("#myModal").modal("show");
    }

});


// ****************************************************
/**
*   Welcome Controller
*   @param $scope
*   @param $http
*   @param myConfig
*
*/
routeAppControllers.controller('initController', function($scope, $http, myConfig, FileUploader){

    // Variable to display tab "Configuration", "Attack Graph" and "Attack Path"
    $scope.show = true;

// **************** File Uploader **************
    var uploader = $scope.uploader = new FileUploader({
        url: myConfig.url + "/initialize",
        withCredentials : true
    });

    // Filters
    uploader.filters.push({
        name: 'customFilter',
        fn: function(item /*{FileLikeObject}*/, options){
            return this.queue.length < 10;
        }
    });

    // Callbaks
    uploader.onWhenAddingFileFailed = function(item /*{File|FileLikeObject}*/, filter, options){
        console.info('onWhenAddingFileFailed', item, filter, options);
    };
    uploader.onAfterAddingFile = function(fileItem){
        console.info('onAfterAddingFile', fileItem);
    };
    uploader.onBeforeUploadItem =function(item){
        console.info('onBeforeUploadItem', item);
    };
    uploader.onProgressItem = function(fileItem, progress){
        console.info('onProgressItem', fileItem, progress);
    };
    uploader.onProgressAll = function(progress){
        console.info('onProgressAll', progress);
    };
    uploader.onSuccessItem = function(fileItem, response, status, headers){
        console.info('onSuccessItem', fileItem, response, status, headers);
    };
    uploader.onErrorItem = function(fileItem, response, status, headers){
        console.info('onErrorItem', fileItem, response, status, headers);
	alert("failed to upload the topology to \n " + myConfig.url + "/initialize");
    };
    uploader.onCancelItem = function(fileItem, response, status, headers){
        console.info('onCancelItem', fileItem, response, status, headers);
    };
    uploader.onCompleteItem = function(fileItem, response, status, headers){
        console.info('onCompleteItem', fileItem, response, status, headers);
    };
    uploader.onCompleteAll = function(){
        console.info('onCompleteAll');
        $scope.show = true;
        alert("Attack graph generated. Ready for analysis.");
    };
    console.info('uploader', uploader);

});
