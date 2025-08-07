# import pandas as pd
# import os
#
# import igraph as ig
# from dateutil import parser
#
# def parse_timestamp(timestamp):
#     return parser.isoparse(timestamp)
# def create_login_graph(df_signin, save_path=None):
#     G = ig.Graph(directed=True)
#     node_map = {}  # To keep track of nodes and their indices
#
#
#     # Add user-app-resource interactions from df_signin with weights and timestamps
#     for _, row in df_signin.iterrows():
#         # user_node = f'user_{row["userId"]}'
#         # app_node = f'app_{row["appId"]}'
#         # resource_node = f'resource_{row["resourceId"]}'
#         user_node = f'{row["userId"]}'
#         app_node = f'{row["appId"]}'
#         resource_node = f'{row["resourceId"]}'
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
#         # Add edges with weights, timestamps, and user attribute
#         if G.are_adjacent(user_index, app_index):
#             eid = G.get_eid(user_index, app_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#             G.es[eid]['user'] = row['userId']  # Add the user attribute
#             G.es[eid]['is_src_client'] = True
#         else:
#             G.add_edge(user_index, app_index, action='login', weight=1, time=[timestamp], user=row['userId'], is_src_client=True)
#
#         if G.are_adjacent(app_index, resource_index):
#             eid = G.get_eid(app_index, resource_index)
#             G.es[eid]['weight'] += 1
#             G.es[eid]['time'].append(timestamp)
#             G.es[eid]['user'] = row['userId']  # Add the user attribute
#             G.es[eid]['is_src_client'] = True
#         else:
#             G.add_edge(app_index, resource_index, action='access', weight=1, time=[timestamp], user=row['userId'], is_src_client=True)
#
#     # Save the graph if a save path is provided
#     if save_path:
#         G.write_pickle(save_path)
#
#     return G
#
# # Create necessary directories
# os.makedirs('data/input', exist_ok=True)
# os.makedirs('data/output', exist_ok=True)
#
# # Define input and output paths
# input_path = 'data/input/'
# output_path = 'data/output/data_full.csv'
#
# # Read CSV files
# df_users = pd.read_csv(f'{input_path}usersALL.csv')
# df_signin = pd.read_csv(f'{input_path}properties-signinlogsALL.csv')
# df_service = pd.read_csv(f'{input_path}properties-serviceprincipalsigninlogsAll.csv')
# df_non_in = pd.read_csv(f'{input_path}properties-noninteractiveusersigninlogs.csv')
#
# # Combine dataframes
# data = pd.concat([df_signin, df_non_in], ignore_index=True)
#
# # Select required columns
# columns = ['createdDateTime', 'appId', 'resourceId', 'userId', 'location.city', 'userPrincipalName', 'authenticationDetails']
# data = data[columns]
#
# def determine_protocol(auth_details):
#     if isinstance(auth_details, list) and auth_details:
#         for detail in auth_details:
#             method = detail.get('authenticationMethod', '').lower()
#             if 'password' in method:
#                 return 'Password'
#             elif any(x in method for x in ['mobile app', 'sms', 'phone call']):
#                 return 'Multi-Factor Authentication'
#             elif 'token' in method or 'token' in detail.get('authenticationStepResultDetail', '').lower():
#                 return 'Token-Based'
#     return 'Others'
#
# # Data processing
# data['time'] = pd.to_datetime(data['createdDateTime'], utc=True)
# data = data.sort_values(by='time')
#
# # Calculate USER_AGE and MACHINE_AGE
# now = pd.Timestamp.now(tz='UTC')
# data['USER_AGE'] = (now - data.groupby('userId')['time'].transform('min')).dt.days
# data['MACHINE_AGE'] = (now - data.groupby('appId')['time'].transform('min')).dt.days
# data['MACHINE_EARLIEST_DATE'] = data.groupby('userId')['time'].transform('min')
#
# # Add new columns
# data['DAY_COL'] = data['time'].dt.day
# data['PROTOCOL'] = data['authenticationDetails'].apply(lambda x: determine_protocol(eval(x)))
# data['DATASET'] = data['PROTOCOL'].apply(lambda x: x if x in ['Password', 'Multi-Factor Authentication', 'Token-Based'] else 'Others')
# data['date'] = data['time'].dt.date
#
# # Calculate NUM_INBOUND_DAYS
# unique_days = data.groupby('appId')['date'].nunique().reset_index(name='NUM_INBOUND_DAYS')
# data = data.merge(unique_days, on='appId', how='left')
#
# # Convert 'createdDateTime' to datetime without timezone info
# data['createdDateTime'] = pd.to_datetime(data['createdDateTime']).dt.strftime('%Y-%m-%d %H:%M:%S')
# data['createdDateTime'] = pd.to_datetime(data['createdDateTime'])
#
# # Function to generate anonymized ID mappings
# def generate_id_mappings(column, prefix):
#     unique_ids = column.unique()
#     return {id_: f"{prefix}{i+1:03d}" for i, id_ in enumerate(unique_ids)}
#
# # Generate mappings for each type of ID
# user_id_mapping = generate_id_mappings(data['userId'], 'U')
# app_id_mapping = generate_id_mappings(pd.concat([data['appId'], df_service['appId']]), 'A')
# resource_id_mapping = generate_id_mappings(pd.concat([data['resourceId'], df_service['resourceId']]), 'R')
# user_principal_name_mapping = generate_id_mappings(data['userPrincipalName'], 'UPN')
#
# # Apply mappings to the dataframes
# data['userId'] = data['userId'].map(user_id_mapping)
# data['appId'] = data['appId'].map(app_id_mapping)
# data['resourceId'] = data['resourceId'].map(resource_id_mapping)
# data['userPrincipalName'] = data['userPrincipalName'].map(user_principal_name_mapping)
#
# df_service['appId'] = df_service['appId'].map(app_id_mapping)
# df_service['resourceId'] = df_service['resourceId'].map(resource_id_mapping)
#
# # Save the processed DataFrame
# data.to_csv(output_path, index=False)
#
# print(f"Data processing complete. Output saved to {output_path}")
#
#
# create_login_graph(data,"data/output/login_graph.v2.pkl")
# print(f"Graph creation is complete. Output saved to {output_path}")
import pandas as pd
import os
import igraph as ig
from dateutil import parser
from typing import Dict, Any, Tuple
import ipaddress

# Constants
INPUT_DIR = 'data/input/'
OUTPUT_DIR = 'data/output/'
GRAPH_OUTPUT = 'login_graph.v3.pkl'

def get_subnet(ip, prefix_length=24):
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return str(network)
    except ValueError:
        return None

# Adding SRC_SUBNET column
def create_directories():
    """Create necessary input and output directories."""
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def read_csv_files() -> Dict[str, pd.DataFrame]:
    """Read CSV files and return a dictionary of DataFrames."""
    try:
        return {
            'users': pd.read_csv(f'{INPUT_DIR}usersALL.csv'),
            'signin': pd.read_csv(f'{INPUT_DIR}properties-signinlogsALL.csv'),
            'service': pd.read_csv(f'{INPUT_DIR}properties-serviceprincipalsigninlogsAll.csv',low_memory=False),
            'non_interactive': pd.read_csv(f'{INPUT_DIR}properties-noninteractiveusersigninlogs.csv',low_memory=False)
        }
    except FileNotFoundError as e:
        print(f"Error reading CSV files: {e}")
        raise

def determine_protocol(auth_details: Any) -> str:
    """Determine the authentication protocol from auth details."""
    if isinstance(auth_details, list) and auth_details:
        for detail in auth_details:
            method = detail.get('authenticationMethod', '').lower()
            if 'password' in method:
                return 'Password'
            elif any(x in method for x in ['mobile app', 'sms', 'phone call']):
                return 'Multi-Factor Authentication'
            elif 'token' in method or 'token' in detail.get('authenticationStepResultDetail', '').lower():
                return 'Token-Based'
    return 'Others'


def process_data(df_signin: pd.DataFrame, df_non_in: pd.DataFrame) -> pd.DataFrame:
    """Process and combine signin data."""
    data = pd.concat([df_signin, df_non_in], ignore_index=True)
    columns = ['createdDateTime', 'appId', 'resourceId', 'userId', 'location.city', 'userPrincipalName',
               'authenticationDetails','ipAddress']
    data = data[columns]
    data['SRC_SUBNET'] = data['ipAddress'].apply(lambda ip: get_subnet(ip))

    data['time'] = pd.to_datetime(data['createdDateTime'], utc=True)
    data = data.sort_values(by='time')

    now = pd.Timestamp.now(tz='UTC')
    data['USER_AGE'] = (now - data.groupby('userId')['time'].transform('min')).dt.days
    data['MACHINE_AGE'] = (now - data.groupby('appId')['time'].transform('min')).dt.days
    data['MACHINE_EARLIEST_DATE'] = data.groupby('userId')['time'].transform('min')

    data['DAY_COL'] = data['time'].dt.day
    data['PROTOCOL'] = data['authenticationDetails'].apply(lambda x: determine_protocol(eval(x)))
    data['DATASET'] = data['PROTOCOL'].apply(
        lambda x: x if x in ['Password', 'Multi-Factor Authentication', 'Token-Based'] else 'Others')
    data['date'] = data['time'].dt.date

    unique_days = data.groupby('appId')['date'].nunique().reset_index(name='NUM_INBOUND_DAYS')
    data = data.merge(unique_days, on='appId', how='left')

    data['createdDateTime'] = pd.to_datetime(data['createdDateTime']).dt.strftime('%Y-%m-%d %H:%M:%S')
    data['createdDateTime'] = pd.to_datetime(data['createdDateTime'])

    return data


def generate_id_mappings(column: pd.Series, prefix: str) -> Dict[Any, str]:
    """Generate anonymized ID mappings."""
    unique_ids = column.unique()
    return {id_: f"{prefix}{i + 1:03d}" for i, id_ in enumerate(unique_ids)}


# def anonymize_data(data: pd.DataFrame, df_service: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
#     """Anonymize data in both dataframes."""
#     user_id_mapping = generate_id_mappings(data['userId'], 'U')
#     app_id_mapping = generate_id_mappings(pd.concat([data['appId'], df_service['appId']]), 'A')
#     resource_id_mapping = generate_id_mappings(pd.concat([data['resourceId'], df_service['resourceId']]), 'R')
#     user_principal_name_mapping = generate_id_mappings(data['userPrincipalName'], 'UPN')
#
#     data['userId'] = data['userId'].map(user_id_mapping)
#     data['appId'] = data['appId'].map(app_id_mapping)
#     data['resourceId'] = data['resourceId'].map(resource_id_mapping)
#     data['userPrincipalName'] = data['userPrincipalName'].map(user_principal_name_mapping)
#
#     df_service['appId'] = df_service['appId'].map(app_id_mapping)
#     df_service['resourceId'] = df_service['resourceId'].map(resource_id_mapping)
#
#     return data, df_service

def anonymize_data(data: pd.DataFrame, df_service: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Anonymize data in both dataframes."""
    user_id_mapping = generate_id_mappings(data['userId'], 'U')
    app_id_mapping = generate_id_mappings(pd.concat([data['appId'], df_service['appId']]), 'A')
    resource_id_mapping = generate_id_mappings(pd.concat([data['resourceId'], df_service['resourceId']]), 'R')
    user_principal_name_mapping = generate_id_mappings(data['userPrincipalName'], 'UPN')
    ip_mapping = generate_id_mappings(data['ipAddress'], 'IP')
    subnet_mapping = generate_id_mappings(data['SRC_SUBNET'], 'SNET')

    data['userId'] = data['userId'].map(user_id_mapping)
    data['appId'] = data['appId'].map(app_id_mapping)
    data['resourceId'] = data['resourceId'].map(resource_id_mapping)
    data['userPrincipalName'] = data['userPrincipalName'].map(user_principal_name_mapping)
    data['ipAddress'] = data['ipAddress'].map(ip_mapping)
    data['SRC_SUBNET'] = data['SRC_SUBNET'].map(subnet_mapping)

    df_service['appId'] = df_service['appId'].map(app_id_mapping)
    df_service['resourceId'] = df_service['resourceId'].map(resource_id_mapping)

    return data, df_service

def create_login_graph(df_signin: pd.DataFrame, save_path: str) -> ig.Graph:
    """Create a login graph from signin data."""
    G = ig.Graph(directed=True)
    node_map = {}

    for _, row in df_signin.iterrows():
        user_node = f'{row["userId"]}'
        app_node = f'{row["appId"]}'
        resource_node = f'{row["resourceId"]}'
        timestamp = row['createdDateTime']

        for node, node_type in [(user_node, 'user'), (app_node, 'app'), (resource_node, 'resource')]:
            if node not in node_map:
                G.add_vertex(name=node, type=node_type, label=node)
                node_map[node] = G.vs.find(name=node).index

        user_index, app_index, resource_index = [node_map[node] for node in [user_node, app_node, resource_node]]

        for edge in [(user_index, app_index, 'login'), (app_index, resource_index, 'access')]:
            if G.are_adjacent(*edge[:2]):
                eid = G.get_eid(*edge[:2])
                G.es[eid]['weight'] += 1
                G.es[eid]['time'].append(timestamp)
                G.es[eid]['user'] = row['userId']
                G.es[eid]['is_src_client'] = True
            else:
                G.add_edge(*edge[:2], action=edge[2], weight=1, time=[timestamp], user=row['userId'], is_src_client=True)

    if save_path:
        G.write_pickle(save_path)

    return G


def main():
    create_directories()

    # try:
    df_dict = read_csv_files()
    data = process_data(df_dict['signin'], df_dict['non_interactive'])
    data, df_service = anonymize_data(data, df_dict['service'])
    # Drop ipAddress and time columns as requested
    data = data.drop(columns=['ipAddress', 'time','authenticationDetails'], errors='ignore')


    output_path = f'{OUTPUT_DIR}data_full_second.csv'
    data.to_csv(output_path, index=False)
    print(f"Data processing complete. Output saved to {output_path}")

    graph_path = f'{OUTPUT_DIR}{GRAPH_OUTPUT}'
    create_login_graph(data, graph_path)
    print(f"Graph creation is complete. Output saved to {graph_path}")

    # except Exception as e:
    #     print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()