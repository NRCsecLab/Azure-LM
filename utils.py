# import pandas as pd
# import igraph as ig
# import random
# import json
# from datetime import datetime
# import os
# import itertools
# from dateutil import parser
#
# def parse_timestamp(timestamp):
#     return parser.isoparse(timestamp)
#
# def load_dataframe_from_csv(filepath):
#     """Load DataFrame from CSV and convert 'time' column to datetime."""
#     print(f"Loading DataFrame from {filepath}...")
#     df = pd.read_csv(filepath)
#     # if 'createdDateTime' in df.columns:
#     #     df['createdDateTime'] = pd.to_datetime(df['createdDateTime'])
#     print("DataFrame loaded.")
#     return df
#
# def load_json(filepath):
#     """Load data from a JSON file."""
#     with open(filepath, 'r') as f:
#         data = set(json.load(f))
#     print(f"Data loaded from {filepath}")
#     return data
#
# def load_and_process_data(output_folder='data/processed_data/', auth_data_path='data/properties-signinlogsAnoy.csv'):
#     """Central function to load and process data using Pandas."""
#     auth_df = load_dataframe_from_csv(auth_data_path)
#
#     # non_compromise_hosts_path = os.path.join(output_folder, 'non_compromise_hosts.json')
#     # uninteresting_dst_path = os.path.join(output_folder, 'uninteresting_dst.json')
#     #
#     # NON_COMPROMISE_HOSTS = load_json(non_compromise_hosts_path)
#     # UNINTERESTING_DST = load_json(uninteresting_dst_path)
#
#     print("Data is ready for use.")
#     return auth_df #, UNINTERESTING_DST, NON_COMPROMISE_HOSTS
#
# def safe_rand_sample(item_list, num_samples):
#     """Return a random sample of items, ensuring not to exceed list length."""
#     if isinstance(item_list, set):
#         item_list = list(item_list)
#     return random.sample(item_list, min(num_samples, len(item_list)))
#
# def get_random_users(sampling_ratio, G):
#     """Return a set of employee user names from the graph."""
#     if sampling_ratio <= 0:
#         raise ValueError("Sampling ratio must be greater than 0")
#
#     users = [v['name'] for v in G.vs if v['type'] == 'user']
#     sampled_users = safe_rand_sample(users, int(sampling_ratio * len(users)))
#
#     print("Selecting Users.......")
#     print(sampled_users[:10])  # Print the first 10 selected users for debugging
#     return set(sampled_users)
#
# def get_all_users():
#     """Return the precomputed set of all employee user names."""
#     return _cached_users
#
# def get_sysadmin_users(auth_df):
#     """Return a set of all sysadmin user names."""
#     valid_logins = auth_df[auth_df['is_sysadmin'] == 1]
#     return set(valid_logins['user'])
#
# def remove_spurious_logins(logins):
#     """Remove logins between equivalent machines or from management into clients."""
#     return logins[logins['appId'] != logins['resourceId']]
#
# def create_login_graph(df_signin, df_service = None):
#     """
#     Create a weighted directed graph from the provided Azure dataframes.
#
#     Parameters:
#     - df_signin (pd.DataFrame): DataFrame containing user-app-resource interactions.
#     - df_service (pd.DataFrame): DataFrame containing service principal-resource interactions.
#
#     Returns:
#     - G (ig.Graph): A directed graph with weighted edges.
#     """
#     G = ig.Graph(directed=True)
#     node_map = {}  # To keep track of nodes and their indices
#
#     # Add user-app-resource interactions from df_signin with weights and timestamps
#     for _, row in df_signin.iterrows():
#         user_node = f'user_{row["userId"]}'
#         app_node = f'app_{row["appId"]}'
#         resource_node = f'resource_{row["resourceId"]}'
#         timestamp = parse_timestamp(row['createdDateTime'])
#
#         # Add nodes if they don't exist
#         if user_node not in node_map:
#             G.add_vertex(name=user_node, type='user', label=row['userId'])
#             node_map[user_node] = G.vs.find(name=user_node).index
#         if app_node not in node_map:
#             G.add_vertex(name=app_node, type='app', label=row['appId'])
#             node_map[app_node] = G.vs.find(name=app_node).index
#         if resource_node not in node_map:
#             G.add_vertex(name=resource_node, type='resource', label=row['resourceId'])
#             node_map[resource_node] = G.vs.find(name=resource_node).index
#
#         user_index = node_map[user_node]
#         app_index = node_map[app_node]
#         resource_index = node_map[resource_node]
#
#         # Add edges with weights and timestamps
#         if G.are_adjacent(user_index, app_index):
#             eid = G.get_eid(user_index, app_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#         else:
#             G.add_edge(user_index, app_index, action='login', weight=1, time=[timestamp])
#
#         if G.are_adjacent(app_index, resource_index):
#             eid = G.get_eid(app_index, resource_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#         else:
#             G.add_edge(app_index, resource_index, action='access', weight=1, time=[timestamp])
#
#     # # Add service principal interactions from df_service with weights and timestamps
#     # for _, row in df_service.iterrows():
#     #     service_app_node = f'service_app_{row["appId"]}'
#     #     resource_node = f'resource_{row["resourceId"]}'
#     #     timestamp = parse_timestamp(row['createdDateTime'])
#     #
#     #     if service_app_node not in node_map:
#     #         G.add_vertex(name=service_app_node, type='service_app', label=row['appId'])
#     #         node_map[service_app_node] = G.vs.find(name=service_app_node).index
#     #     if resource_node not in node_map:
#     #         G.add_vertex(name=resource_node, type='resource', label=row['resourceId'])
#     #         node_map[resource_node] = G.vs.find(name=resource_node).index
#     #
#     #     service_app_index = node_map[service_app_node]
#     #     resource_index = node_map[resource_node]
#     #
#     #     if G.are_connected(service_app_index, resource_index):
#     #         eid = G.get_eid(service_app_index, resource_index)
#     #         G.es[eid]['weight'] += 1
#     #         G.es[eid]['time'].append(timestamp)
#     #     else:
#     #         G.add_edge(service_app_index, resource_index, action='service access', weight=1, time=[timestamp])
#
#     return G
#
#
# def flatten_list(list_of_lists):
#     """Flatten a list of lists into a single list."""
#     return list(itertools.chain(*list_of_lists))
#
# def df_to_grouped_dict(df, key_cols, value_col, agg_func):
#     """Convert DataFrame to a dictionary grouped by key columns."""
#     return df.groupby(key_cols)[value_col].agg(agg_func).to_dict()
#
# def print_small_divider():
#     print("-----------------------------------------------------\n")
#
# def print_divider():
#     """Print a divider line."""
#     print("================================================================\n")
#
# def comma_num(number):
#     """Return a str with a comma for every thousand."""
#     return "{:,}".format(number)
#
# # Example usage
# df_signin =load_and_process_data('data/properties-signinlogsAnoy.csv')
# print(df_signin.columns)
# G = create_login_graph(df_signin)
# _cached_users = get_random_users(0.3, G)
# print(len(_cached_users))
import pandas as pd
import igraph as ig
import random
import json
from datetime import datetime
import os
import itertools
from dateutil import parser

def parse_timestamp(timestamp):
    return parser.isoparse(timestamp)

def load_dataframe_from_csv(filepath):
    """Load DataFrame from CSV and convert 'time' column to datetime."""
    print(f"Loading DataFrame from {filepath}...")
    df = pd.read_csv(filepath)
    # if 'createdDateTime' in df.columns:
    #     df['createdDateTime'] = pd.to_datetime(df['createdDateTime'])
    print("DataFrame loaded.")
    return df

def load_json(filepath):
    """Load data from a JSON file."""
    with open(filepath, 'r') as f:
        data = set(json.load(f))
    print(f"Data loaded from {filepath}")
    return data

def load_and_process_data(output_folder='data/processed_data/', auth_data_path='data/all.csv'):
    """Central function to load and process data using Pandas."""
    auth_df = load_dataframe_from_csv(auth_data_path)

    # non_compromise_hosts_path = os.path.join(output_folder, 'non_compromise_hosts.json')
    # uninteresting_dst_path = os.path.join(output_folder, 'uninteresting_dst.json')
    #
    # NON_COMPROMISE_HOSTS = load_json(non_compromise_hosts_path)
    # UNINTERESTING_DST = load_json(uninteresting_dst_path)

    print("Data is ready for use.")
    return auth_df #, UNINTERESTING_DST, NON_COMPROMISE_HOSTS

def safe_rand_sample(item_list, num_samples):
    """Return a random sample of items, ensuring not to exceed list length."""
    if isinstance(item_list, set):
        item_list = list(item_list)
    return random.sample(item_list, min(num_samples, len(item_list)))

def get_random_users(sampling_ratio, G):
    """Return a set of employee user names from the graph."""
    if sampling_ratio <= 0:
        raise ValueError("Sampling ratio must be greater than 0")

    users = [v['name'] for v in G.vs if v['type'] == 'user']
    # users = {user.split('_')[1] for user in users}
    sampled_users = safe_rand_sample(users, int(sampling_ratio * len(users)))

    print("Selecting Users.......")
    print(sampled_users[:10])  # Print the first 10 selected users for debugging
    return set(sampled_users)

def get_all_users():
    """Return the precomputed set of all employee user names."""
    global _cached_users
    return _cached_users

def get_sysadmin_users(auth_df):
    """Return a set of all sysadmin user names."""
    valid_logins = auth_df[auth_df['is_sysadmin'] == 1]
    return set(valid_logins['user'])

def remove_spurious_logins(logins):
    """Remove logins between equivalent machines or from management into clients."""
    return logins[logins['appId'] != logins['resourceId']]


# def create_login_graph(df_signin, df_service=None):
#     """
#     Create a weighted directed graph from the provided Azure dataframes.
#
#     Parameters:
#     - df_signin (pd.DataFrame): DataFrame containing user-app-resource interactions.
#     - df_service (pd.DataFrame): DataFrame containing service principal-resource interactions.
#
#     Returns:
#     - G (ig.Graph): A directed graph with weighted edges.
#     """
#     G = ig.Graph(directed=True)
#     node_map = {}  # To keep track of nodes and their indices
#
#     # Add user-app-resource interactions from df_signin with weights and timestamps
#     for _, row in df_signin.iterrows():
#         user_node = f'user_{row["userId"]}'
#         app_node = f'app_{row["appId"]}'
#         resource_node = f'resource_{row["resourceId"]}'
#         timestamp = parse_timestamp(row['createdDateTime'])
#
#         # Add nodes if they don't exist
#         if user_node not in node_map:
#             G.add_vertex(name=user_node, type='user', label=row['userId'])
#             node_map[user_node] = G.vs.find(name=user_node).index
#         if app_node not in node_map:
#             G.add_vertex(name=app_node, type='app', label=row['appId'])
#             node_map[app_node] = G.vs.find(name=app_node).index
#         if resource_node not in node_map:
#             G.add_vertex(name=resource_node, type='resource', label=row['resourceId'])
#             node_map[resource_node] = G.vs.find(name=resource_node).index
#
#         user_index = node_map[user_node]
#         app_index = node_map[app_node]
#         resource_index = node_map[resource_node]
#
#         # Add edges with weights and timestamps
#         if G.are_adjacent(user_index, app_index):
#             eid = G.get_eid(user_index, app_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#             G.es[eid]['is_src_client'] = True
#         else:
#             G.add_edge(user_index, app_index, action='login', weight=1, time=[timestamp], is_src_client=True)
#
#         if G.are_adjacent(app_index, resource_index):
#             eid = G.get_eid(app_index, resource_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#             G.es[eid]['is_src_client'] = True
#         else:
#             G.add_edge(app_index, resource_index, action='access', weight=1, time=[timestamp], is_src_client=True)
#
#     return G
def create_login_graph(df_signin, df_service=None):
    G = ig.Graph(directed=True)
    node_map = {}  # To keep track of nodes and their indices

    # Add user-app-resource interactions from df_signin with weights and timestamps
    for _, row in df_signin.iterrows():
        # user_node = f'user_{row["userId"]}'
        # app_node = f'app_{row["appId"]}'
        # resource_node = f'resource_{row["resourceId"]}'
        user_node = f'{row["userId"]}'
        app_node = f'{row["appId"]}'
        resource_node = f'{row["resourceId"]}'
        timestamp = parse_timestamp(row['createdDateTime'])

        # Add nodes if they don't exist
        if user_node not in node_map:
            G.add_vertex(name=user_node, type='user', label=row['userId'])
            node_map[user_node] = G.vs.find(name=user_node).index
        if app_node not in node_map:
            G.add_vertex(name=app_node, type='app', label=row['appId'])
            node_map[app_node] = G.vs.find(name=app_node).index
        if resource_node not in node_map:
            G.add_vertex(name=resource_node, type='resource', label=row['resourceId'])
            node_map[resource_node] = G.vs.find(name=resource_node).index

        user_index = node_map[user_node]
        app_index = node_map[app_node]
        resource_index = node_map[resource_node]

        # Add edges with weights, timestamps, and user attribute
        if G.are_adjacent(user_index, app_index):
            eid = G.get_eid(user_index, app_index)
            G.es[eid]['weight'] += 1
            G.es[eid]['time'].append(timestamp)
            G.es[eid]['user'] = row['userId']  # Add the user attribute
            G.es[eid]['is_src_client'] = True
        else:
            G.add_edge(user_index, app_index, action='login', weight=1, time=[timestamp], user=row['userId'], is_src_client=True)

        if G.are_adjacent(app_index, resource_index):
            eid = G.get_eid(app_index, resource_index)
            G.es[eid]['weight'] += 1
            G.es[eid]['time'].append(timestamp)
            G.es[eid]['user'] = row['userId']  # Add the user attribute
            G.es[eid]['is_src_client'] = True
        else:
            G.add_edge(app_index, resource_index, action='access', weight=1, time=[timestamp], user=row['userId'], is_src_client=True)

    return G

def is_server_jump_host(machine):
    """Is the machine a jump host that doesn't allow cred switching?"""
    pass
def flatten_list(list_of_lists):
    """Flatten a list of lists into a single list."""
    return list(itertools.chain(*list_of_lists))

def df_to_grouped_dict(df, key_cols, value_col, agg_func):
    """Convert DataFrame to a dictionary grouped by key columns."""
    return df.groupby(key_cols)[value_col].agg(agg_func).to_dict()

def print_small_divider():
    print("-----------------------------------------------------\n")

def print_divider():
    """Print a divider line."""
    print("================================================================\n")

def comma_num(number):
    """Return a str with a comma for every thousand."""
    return "{:,}".format(number)

df_signin = load_and_process_data()
G = create_login_graph(df_signin)
_cached_users = get_random_users(0.3, G)

if __name__ == "__main__":
    from dateutil import parser


    def get_edge_timestamps(G, source, target):
        """
        Get the timestamps of edges between the source and target nodes in the graph.

        Parameters:
        - G (ig.Graph): The graph object.
        - source (str): The name of the source node.
        - target (str): The name of the target node.

        Returns:
        - List[datetime]: A list of timestamps for the edges between the source and target nodes.
        """
        try:
            source_vertex = G.vs.find(name=source)
            target_vertex = G.vs.find(name=target)

            edges = G.es.select(_source=source_vertex.index, _target=target_vertex.index)
            timestamps = list(itertools.chain(*[e['time'] for e in edges]))

            return [parser.parse(ts) if isinstance(ts, str) else ts for ts in timestamps]
        except ValueError as e:
            print(f"Error finding vertices or edges: {e}")
            return []


    # Example usage
    source_node = 'user_U006'
    target_node = 'app_A015'
    timestamps = get_edge_timestamps(G, source_node, target_node)
    print(timestamps)