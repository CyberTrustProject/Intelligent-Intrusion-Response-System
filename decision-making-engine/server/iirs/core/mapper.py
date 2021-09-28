import json
import logging


def mapper(filepath):
    IP_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^0-9]"
    goal_conditions = []
    try:
        with open(filepath) as topology_file:
            topology = json.load(topology_file)["payload"]['attack_graph']
            arcs = topology['arcs']
            vertices = topology['vertices']
    except Exception:
        with open("../" + filepath) as topology_file:
            topology = json.load(topology_file)['attack_graph']
            arcs = topology['arcs']
            vertices = topology['vertices']
    exploit_keys = {}
    security_condition_keys = {}
    exploits_with_edges = {}
    leaf_execcode = []
    p_attempt = {}
    p_success = {}
    leaf_nodes = []
    attacker_keys = {
        1: 'AT-1',
        2: 'AT-2',
        3: 'AT-3'
    }

    exploit_counter = 0
    vertex_counter = 0
    ids_mapping_info = {}
    ids_mapping_info["associations"] = topology["associations"]
    for node in vertices:
        id_ = node['id']
        ids_mapping_info[id_] = node['fact']
        if ("execCode" in ids_mapping_info[id_]) and ("root" in ids_mapping_info[id_]):
            goal_conditions.append("SC-" + str(id_))
        if node['type'] == 'AND':
            tag = 'E-' + str(id_)
            p_attempt[tag] = {}
            p_success[tag] = {}
            exploit_keys[exploit_counter] = tag
            exploit_counter += 1
            pre, post = [], []
            for arc in arcs:
                pre_, post_ = arc['src'], arc['dst']
                if id_ == pre_:
                    post.append('SC-' + str(post_))
                    for type_ in attacker_keys.values():
                        if arc['prob'] != 0:
                            p_attempt[tag][type_] = (arc['prob'], arc['prob'])
                        else:
                            p_attempt[tag][type_] = (0.6, 0.6)
                elif id_ == post_:
                    pre.append('SC-' + str(pre_))
                    for type_ in attacker_keys.values():
                        p_success[tag][type_] = arc['prob'] if arc['prob'] != 0 else 0.5

            exploits_with_edges[tag] = [pre, post]
        else:
            if node['type'] == 'LEAF':
                leaf_nodes.append('SC-' + str(id_))
                if 'execCode' in node['fact']:
                    leaf_execcode.append('SC-' + str(id_))

            security_condition_keys[vertex_counter] = 'SC-' + str(id_)
            vertex_counter += 1

    logging.debug('[MAPPER] Goal conditions: {0}'.format(goal_conditions))
    return exploit_keys, security_condition_keys, exploits_with_edges, attacker_keys, p_attempt, p_success, leaf_nodes, ids_mapping_info, goal_conditions, leaf_execcode
