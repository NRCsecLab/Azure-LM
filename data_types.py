# import pandas as pd
# from collections import namedtuple
#
# class LoginColumns(object):
#     """Column name constants for Pandas data."""
#     TIME = "createdDateTime"
#     SRC = "appId"
#     DST = "resourceId"
#     USER = "userId"
#     DAY_COL = "day_column"
#     MOVEMENT_TYPE = "movement_type"
#     PROTOCOL = 'clientAppUsed'  # Adapted to Azure dataset column
#     DATASET = "dataset"
#     ATTACK = 'is_attack'
#     ATTACK_ID = 'attack_id'
#
# class EnrichmentColumns:
#     LOCATION = "location.city"
#     MACHINE_AGE = "machine_age"
#     NUM_INBOUND_DAYS = "src_n_days_recv_inbound_success"
#     DEVICE_ID = "deviceDetail.deviceId"
#     OPERATING_SYSTEM = "deviceDetail.operatingSystem"
#     BROWSER = "deviceDetail.browser"
#
# # class EnrichmentColumns(object):
# #     """Class for defining intermediate/enrichment related columns."""
# #     SRC_SUBNET = 'src_subnet'
# #     SRC_LOCATION = "src_location"
# #     LOCATION = "location"
# #     MACHINE_AGE = "machine_age"
# #     MACHINE_EARLIEST_DATE = "machine_first_date"
# #     NUM_INBOUND_DAYS = "src_n_days_recv_inbound_success"
# #     SRC_CLIENT = "is_src_client"
# #     DST_CLIENT = "is_dst_client"
# #     SRC_OWNER = "owner"
# #     USER_TEAM = "user_team"
# #     USER_AGE = "user_age"
#
# class MovementTypes(object):
#     MOVE_FROM_CLIENT = "movement:client-server"
#     MOVE_INTO_CLIENT = "movement:into-client"
#     MOVE_FROM_SERVER = "movement:server-server"
#
# class ScenarioConstants(object):
#     GOAL_EXPLORATION = "goal=exploration"
#     GOAL_SPREAD = "goal=aggressive-spread"
#     GOAL_TARGETED = "goal=targeted"
#     STEALTH_NONE = "stealth=agnostic"
#     STEALTH_ENDPOINTS = "stealth=only-prev-src-dst-combos"
#     STEALTH_ACTIVE_CREDS = "stealth=only-active-src-user-combos"
#     STEALTH_FULL = "stealth=full-stealthiness"
#
# #########################################
# # Base classes
# #########################################
#
# class LoggingClass(object):
#     """Enable different logging output."""
#     def __init__(self, verbose=True):
#         self.verbose = verbose
#
#     def log(self, msg):
#         """HELPER Method: Log message depending on verbose or not."""
#         if self.verbose:
#             print(msg)
#
# class AttackHistory(LoggingClass):
#     """Track history + state of the attack."""
#     def __init__(self, start_state, verbose=True):
#         super(AttackHistory, self).__init__(verbose=verbose)
#         self.start_state = start_state
#         self.attack_path = pd.DataFrame()
#         self.num_hops = 1
#         self.compromised_creds_per_dst = dict()
#         self.visited_dst = set([self.start_state.start_src,])
#         self.cur_machine = self.start_state.start_src
#         self.cur_user = self.start_state.start_user
#         self.last_move_time = self.start_state.start_time
#
#     def get_start_accessible_dst(self):
#         """Get a set of machines that start user has permissions to access."""
#         return self.start_state.start_accessible_dst
#
#     def get_start_src(self):
#         return self.start_state.start_src
#
#     def get_start_user(self):
#         return self.start_state.start_user
#
#     def get_current_user(self):
#         return self.cur_user
#
#     def get_current_machine(self):
#         return self.cur_machine
#
#     def get_visited_dst(self):
#         return self.visited_dst
#
#     def add_new_hop(self, new_hop):
#         """Update attack history with new hop."""
#         self.attack_path = pd.concat([self.attack_path, new_hop], sort=False)
#         self.cur_user = new_hop[LoginColumns.USER].iloc[0]
#         new_machine = new_hop[LoginColumns.DST].iloc[0]
#         self.cur_machine = new_machine
#         self.visited_dst.add(new_machine)
#         self.last_move_time = new_hop[LoginColumns.TIME].iloc[0]
#         self.num_hops += 1
#
#     def update_compromised_creds(self, machine, compromised_creds):
#         """Update compromised creds per machine."""
#         self.compromised_creds_per_dst[machine] = self.compromised_creds_per_dst.get(
#             machine, set([])
#         ) | compromised_creds
#
# AttackNextHop = namedtuple(
#     'AttackNextHop', [LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER])

import pandas as pd
from collections import namedtuple
from utils import G

class LoginColumns(object):
    """Column name constants for Pandas data."""
    TIME = "createdDateTime"
    SRC = "appId"
    DST = "resourceId"
    USER = "userId"
    DAY_COL = "DAY_COL"
    # MOVEMENT_TYPE = "movement_type"
    PROTOCOL = 'PROTOCOL'  # Adapted to Azure dataset column
    DATASET = "DATASET"
    ATTACK = 'is_attack'
    ATTACK_ID = 'attack_id'

class EnrichmentColumns:
    SRC_SUBNET = 'SRC_SUBNET'
    LOCATION = "location.city"

    # Machine Age: first date appeared
    MACHINE_AGE = "MACHINE_AGE"
    MACHINE_EARLIEST_DATE = "MACHINE_EARLIEST_DATE"

    # Node Attribute Labeling
    NUM_INBOUND_DAYS = "NUM_INBOUND_DAYS"
    # SRC_CLIENT = "is_src_client"
    # DST_CLIENT = "is_dst_client"
    SRC_OWNER = "userPrincipalName"

    # USER Features
    # USER_TEAM = "user_team"
    USER_AGE = "USER_AGE"  # how many days since LOCAL LOGIN or remote login

class MovementTypes(object):
    MOVE_FROM_CLIENT = "movement:client-server"
    MOVE_INTO_CLIENT = "movement:into-client"
    MOVE_FROM_SERVER = "movement:server-server"

class ScenarioConstants(object):
    GOAL_EXPLORATION = "goal=exploration"
    GOAL_SPREAD = "goal=aggressive-spread"
    GOAL_TARGETED = "goal=targeted"
    STEALTH_NONE = "stealth=agnostic"
    STEALTH_ENDPOINTS = "stealth=only-prev-src-dst-combos"
    STEALTH_ACTIVE_CREDS = "stealth=only-active-src-user-combos"
    STEALTH_FULL = "stealth=full-stealthiness"

class LoggingClass(object):
    """Enable different logging output."""
    def __init__(self, verbose=True):
        self.verbose = verbose

    def log(self, msg):
        """HELPER Method: Log message depending on verbose or not."""
        if self.verbose:
            print(msg)

class AttackHistory(LoggingClass):
    def __init__(self, start_state, login_graph, verbose=True):
        super(AttackHistory, self).__init__(verbose=verbose)
        self.start_state = start_state
        self.login_graph = G  # Store the graph for later use
        self.attack_path = pd.DataFrame()
        self.num_hops = 1
        self.compromised_creds_per_dst = dict()
        self.visited_dst = set([self.start_state.start_src])
        self.cur_machine = self.start_state.start_src
        self.cur_user = self.start_state.start_user
        self.last_move_time = self.start_state.start_time

    def pivot_to_user(self, appId):
        """Pivot to another user via a shared app."""
        app_index = self.login_graph.vs.find(name=appId).index
        user_indices = self.login_graph.neighbors(app_index, mode="in")
        users = [self.login_graph.vs[idx]['name'] for idx in user_indices if self.login_graph.vs[idx]['type'] == 'user']

        for user in users:
            if user not in self.visited_dst:
                self.visited_dst.add(user)
                return user
        return None

    def get_users_with_access(self, appId):
        """Get a list of users who can access a given app."""
        app_index = self.login_graph.vs.find(name=appId).index
        user_indices = self.login_graph.neighbors(app_index, mode="in")
        return [self.login_graph.vs[idx]['name'] for idx in user_indices if self.login_graph.vs[idx]['type'] == 'user']

    # Other existing methods...

    def get_start_accessible_dst(self):
        """Get a set of machines that start user has permissions to access."""
        return self.start_state.start_accessible_dst

    def get_start_src(self):
        return self.start_state.start_src

    def get_start_user(self):
        return self.start_state.start_user

    def get_current_user(self):
        return self.cur_user

    def get_current_machine(self):
        return self.cur_machine

    def get_visited_dst(self):
        return self.visited_dst

    def add_new_hop(self, new_hop):
        """Update attack history with new hop."""
        self.attack_path = pd.concat([self.attack_path, new_hop], sort=False)
        self.cur_user = new_hop[LoginColumns.USER].iloc[0]

        new_machine = new_hop[LoginColumns.DST].iloc[0]
        self.cur_machine = new_machine
        self.visited_dst.add(new_machine)

        self.last_move_time = new_hop[LoginColumns.TIME].iloc[0]
        self.num_hops += 1

    def update_compromised_creds(self, machine, compromised_creds):
        """Update compromised creds per machine."""
        self.compromised_creds_per_dst[machine] = self.compromised_creds_per_dst.get(
            machine, set([])
        ) | compromised_creds
AttackNextHop = namedtuple(
    'AttackNextHop', [LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER])


