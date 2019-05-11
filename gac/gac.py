#!/usr/bin/python3

import numpy as np
import networkx as nx

def alert_similarity_graph(alerts, similarity_threshold=0.25):
    '''
        Builds the undirected alert similarity graph. Node labels are the alert UIDs
        `alerts` should be a numpy.ndarray where each row has at least 5 fields: (uid, src_ip, src_prt, dst_ip, dst_prt)
    '''

    assert alerts.shape[0] >= 5

    G = nx.Graph()
    for alert_1 in alerts:
        for alert_2 in alerts:
            uid_1, uid_2 = alert_1[0], alert_2[0]
            if uid_1 == uid_2: continue
            if uid_1 not in G: G.add_node(uid_1)
            if uid_2 not in G: G.add_node(uid_2)
            sim = 0
            for attr_index in range(1, 5):
                if alert_1[attr_index] == alert_2[attr_index]: sim += 0.25
            if sim > similarity_threshold: G.add_edge(uid_1, uid_2)
    return G

def netflow_graph(alerts):
    '''
        Builds a directed graph. IPs are the nodes, direction indicates src and dst in an alert.
    '''
    G = nx.DiGraph()
    
    for alert in alerts:
        src, dst = alert[1], alert[3]
        if src == dst: continue
        if src not in G: G.add_node(src)
        if dst not in G: G.add_node(dst)
        G.add_edge(src, dst)
    return G

def cluster_cliques(G, k=15):
    '''
        Convenience wrapper around nx.algorithms.community.k_clique_communities
    '''
    return nx.algorithms.community.k_clique_communities(G, k)

def get_alerts_by_uid(alerts, uid_list):
    lookup = dict(zip(alerts[:,0], alerts))
    result = list()
    for uid in uid_list:
        result.append(lookup[uid])
    return result

def infer_label(directed_graph):
    '''
        Infers label (one-to-one, one-to-many, many-to-one, many-to-many) for the directed graph.
        The graph should be a netflow_graph.
        The formulae for the match certainty are directly taken from the GAC paper, page 5 section 3.3
        Returns a tuple (match_certainty, label)
    '''

    attackers = list()
    victims = list()
    for node in directed_graph.nodes:
        if directed_graph.in_degree(node) >= 1: victims.append(node)
        if directed_graph.out_degree(node) >= 1: attackers.append(node)

    V = len(directed_graph.nodes)
    A = len(attackers)
    T = len(victims)

    oto = 1/3 * ( (V-A)/(V-1) + (V-T)/(V-1) + (V-abs(A-T))/V ) if V > 1 else 0
    otm = 1/3 * ( (V-A)/(V-1) + T/(V-1) + abs(A-T)/(V-2) ) if V > 2 else 0
    mto = 1/3 * ( A/(V-1) + (V-T)/(V-1) + abs(A-T)/(V-2) ) if V > 2 else 0
    mtm = 1/3 * ( A/V + T/V + (V-abs(A-T))/V ) if V > 0 else 0

    certainty, pattern_name = max((oto, 'oto'), (otm, 'otm'), (mto, 'mto'), (mtm, 'mtm'), key=lambda v: v[0])

    return (certainty, pattern_name, attackers, victims)

def gac_cluster(alerts, similarity_threshold=0.25, clique_size=15):
    '''
        `alerts` should be a numpy.ndarray where each row has at least 5 fields: (uid, src_ip, src_prt, dst_ip, dst_prt). Other fields are not used, but also not discarded.

        Wrapper function to combine building the alert_similarity graph with the label inference from the flow graph.
        Returns labeled clusters of alerts, a list of triples: (pattern_name, match_certainty, alerts_in_clique). alerts_in_clique is a numpy array.
    '''
    g_attr = alert_similarity_graph(alerts, similarity_threshold)
    cliques = cluster_cliques(g_attr, clique_size)

    all_clique_uids = list()
    for clique in list(cliques):
        all_clique_uids.append(list(clique))

    labeled_clusters = list()
    for clique_uids in all_clique_uids:
        
        alerts_in_clique = get_alerts_by_uid(alerts, clique_uids)
        g_flow = netflow_graph(alerts_in_clique)

        certainty, pattern_name, attackers, victims = infer_label(g_flow)
        labeled_clusters.append((certainty, pattern_name, alerts_in_clique, attackers, victims))
    return labeled_clusters

def gac_connect(alerts, similarity_threshold=0.25, clique_size=15):
    pass
    # TODO
    