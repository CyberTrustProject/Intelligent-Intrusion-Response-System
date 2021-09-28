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
*  Defines services
*/
angular.module('myModule', []).service('serviceTest', function(){
    var array, savedGraph, savedData;

  // Getter & setter for initialize and retrieve data
	this.set = function(data){
		savedData = data;
	};
	this.get = function(){
		return savedData;
	};


  // Getter & Setter for remediation simulation
  this.setArray = function(id_path, id_remed){
    array = [id_path, id_remed];
  };
  this.getArray = function(){
    return array;
  };

  this.setGraph = function(graph){
    savedGraph = graph;
  };
  this.getGraph = function(){
    return savedGraph;
  };

});