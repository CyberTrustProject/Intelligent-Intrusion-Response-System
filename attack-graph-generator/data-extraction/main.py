#########################################################################################
# This file is part of FIWARE CyberCAPTOR, instance of Cyber Security Generic Enabler   #
#  Copyright (C) 2012-2015  Thales Services S.A.S.,                                     #
#  20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           #
#                                                                                       #
# FIWARE CyberCAPTOR is free software; you can redistribute                             #  
# it and/or modify it under the terms of the GNU General Public License                 #
# as published by the Free Software Foundation; either version 3 of the License,        #
# or (at your option) any later version.                                                #
#                                                                                       #
# FIWARE CyberCAPTOR is distributed in the hope                                         #
# that it will be useful, but WITHOUT ANY WARRANTY; without even the implied            #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                                          #
#                                                                                       #
# You should have received a copy of the GNU General Public License                     #
# along with FIWARE Cyber Security Generic Enabler.                                     #
# If not, see <http://www.gnu.org/licenses/>.                                           #
#########################################################################################

from topology import Topology, FlowMatrix, VLAN
import argparse

import logging
from database import init_db

def main():

    #Build the Argument parser
    parser = argparse.ArgumentParser(description='Generates attack graph input files from topological files')
    parser.add_argument('--hosts-interfaces-file', dest='hosts_interfaces_file', required=True,
                        help='The CSV file containing the hosts and the interfaces.')
    parser.add_argument('--vlans-file', dest='vlans_file', required=True,
                        help='The CSV file containing the VLANS.')
    parser.add_argument('--vulnerability-scan', dest='vulnerability_scan', required=False, nargs='+',
                        help='The Nessus scanner report file(s).')
    parser.add_argument('--openvas-scan', dest='openvas_vulnerability_scan', required=False, nargs='+',
                        help='The OpenVAS scanner report file(s).')
    parser.add_argument('--flow-matrix-file', dest='flow_matrix_file', required=False,
                        help='The CSV file containing the flow matrix')
    parser.add_argument('--routing-file', dest='routing_file', required=False,
                        help='The CSV file containing the routing informations')

    parser.add_argument('--mulval-output-file', dest='mulval_output_file', required=False,
                        help='The output path where the mulval input file will be stored.')

    parser.add_argument('--to-fiware-xml-topology', dest='to_fiware_xml_topology', required=False,
                        help='The path where the XML topology file should be stored.')

    parser.add_argument('--display-infos', action='store_true', dest='display_infos', required=False,
                        help='Display information and statistics about the topology.')

    parser.add_argument('-v', dest='verbose', action='store_true', default=False,
                        help='Set log printing level to INFO')

    parser.add_argument('-vv', dest='very_verbose', action='store_true', default=False,
                        help='Set log printing level to DEBUG')

    args = parser.parse_args()


    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    if args.very_verbose:
        logging.basicConfig(level=logging.DEBUG)
    if not args.verbose and not args.very_verbose:
        logging.basicConfig(level=logging.WARNING)

    logging.info("Loading the vulnerability database connector.")
    init_db()

    topology = Topology()
    topology.load_from_topological_input_files(args.hosts_interfaces_file, args.vlans_file)

    if args.vulnerability_scan:
        for vulnerabity_scan_file in args.vulnerability_scan:
            topology.add_nessus_report_information(vulnerabity_scan_file)

    if args.openvas_vulnerability_scan:
        for openvas_scan_file in args.openvas_vulnerability_scan:
            topology.add_openvas_report_information(openvas_scan_file)

    if args.flow_matrix_file:
        topology.flow_matrix = FlowMatrix(topology, args.flow_matrix_file)

    if args.routing_file:
        topology.load_routing_file(args.routing_file)
    else:
        logging.info("No flow matrix file has been provided.")
        topology.flow_matrix = FlowMatrix(topology)

    if args.display_infos:
        topology.print_details()

    if args.mulval_output_file:
        topology.to_mulval_input_file(args.mulval_output_file)

    if args.to_fiware_xml_topology:
        topology.to_fiware_topology_file(args.to_fiware_xml_topology)

if __name__ == '__main__':
    main()
