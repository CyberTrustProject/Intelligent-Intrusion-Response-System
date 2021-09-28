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

myApp.filter('listFilter', [function(){
	
/**
*   Filter listFilter
*
*   @param items
*   @param searchText
*
*	items is the complete list of hosts
*	searchText is the substring searched.
*/
	return function(items, searchText){

		if(searchText == undefined){
			filtered = items;
			return filtered;
		}
		else{
			var filtered = [];

			angular.forEach(items, function(item){
				var normalText = item.name;
				var lowerText = item.name.toLowerCase();

				// Manage input with strict case and lower case
				if(normalText.indexOf(searchText) >= 0 || lowerText.indexOf(searchText) >= 0){
					filtered.push(item);
				}
			});
			return filtered;
		}
	};
}]);