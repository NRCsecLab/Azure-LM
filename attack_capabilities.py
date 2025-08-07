# from collections import defaultdict
# from data_types import *
# from utils import *
# import datetime
# from dateutil import tz
# class AttackerCapabilities(LoggingClass):
#     DEFAULT_CRED_EXPOSED_HRS = 24 * 7  # Default time window for exposed credentials (1 week)
#     MAX_COMPROMISED_USERS = 50  # Maximum number of compromised users to process
#
#     def __init__(self, knowledge, compromise_cred_hrs=None, verbose=True):
#         super(AttackerCapabilities, self).__init__(verbose=verbose)
#         self.knowledge = knowledge
#         self.dst_per_compromised_user = defaultdict(set)
#         self.real_users = get_all_users()
#
#         self.compromise_cred_hrs = compromise_cred_hrs or self.DEFAULT_CRED_EXPOSED_HRS
#         self.log(f"Attacker Capabilities set to: {self.knowledge}\tcred exposure window={self.compromise_cred_hrs} hrs\n")
#
#     def _get_new_compromised_users(self, G, time, host):
#         if time.tzinfo is None:
#             time = time.replace(tzinfo=tz.tzutc())
#         lower_bound = time - datetime.timedelta(hours=self.compromise_cred_hrs)
#         if lower_bound.tzinfo is None:
#             lower_bound = lower_bound.replace(tzinfo=tz.tzutc())
#
#         host_vertex = G.vs.find(name=host)
#         app_neighbors = G.neighbors(host_vertex, mode='in')
#
#         valid_edges = []
#         for app_index in app_neighbors:
#             app_vertex = G.vs[app_index]
#             app_edges = G.es.select(_target=app_vertex.index)
#             for edge in app_edges:
#                 if any(lower_bound <= t.replace(tzinfo=tz.tzutc()) <= time for t in edge['time']):
#                     valid_edges.append(edge)
#
#         vuln_users = set()
#         for edge in valid_edges:
#             source_name = G.vs[edge.source]['name']
#             if source_name.startswith('user_'):
#                 user = source_name.split('_')[1]
#                 vuln_users.add(user)
#
#         compromised_users = {u for u in vuln_users if u in self.real_users}
#
#         if compromised_users:
#             compromised_users = set(list(compromised_users)[:self.MAX_COMPROMISED_USERS])
#
#         self.log(
#             f"Updating compromised creds:\tHost = {host} had {len(vuln_users)} users login within past {self.compromise_cred_hrs} hours.\nCompromised (real) user set = {compromised_users}")
#
#         return compromised_users
#
#     def initialize_capabilities(self, start_state, G):
#         self._update_candidate_dst(G, start_state.start_user)
#
#     def update_capabilities(self, new_time, new_dst, G):
#         compromised_users = self._get_new_compromised_users(G, new_time, new_dst)
#         for user in compromised_users:
#             self._update_candidate_dst(G, user)
#
#         return compromised_users
#
#
#     def get_candidate_next_hops(self,  attack_history):
#         candidate_srcs = self._get_candidate_src(attack_history)
#         self.log(f"Candidate Hops: Candidate src = {candidate_srcs}")
#
#         next_hops = []
#         for src in candidate_srcs:
#             connected_resources = self._get_connected_resources(G, src)
#             if not connected_resources:
#                 continue  # Skip apps with no connected resources
#
#             for user, dst in self._get_candidate_user_dst():
#                 if dst in connected_resources:
#                     next_hops.append(AttackNextHop(appId=src, resourceId=dst, userId=user))
#
#         self.log(f"Candidate Hops: {len(next_hops)} possible hops generated")
#         return next_hops
#
#     def _get_connected_resources(self, G, appId):
#         """
#         Get all resources connected to the given app.
#
#         Parameters:
#         - G (ig.Graph): The graph object.
#         - appId (str): The app ID.
#
#         Returns:
#         - connected_resources (set): A set of connected resource IDs.
#         """
#         if appId not in G.vs["name"]:
#             return set()
#
#         app_index = G.vs.find(name=appId).index
#         connected_indices = set(G.neighbors(app_index, mode='out'))
#
#         connected_resources = {G.vs[idx]["name"] for idx in connected_indices if G.vs[idx]["type"] == "resource"}
#
#         return connected_resources
#     def _get_candidate_src(self, attack_history):
#         return attack_history.visited_dst
#
#     def _get_candidate_user_dst(self):
#         user_and_dst_pairs = generate_user_dst_pairs(self.dst_per_compromised_user)
#         user_and_dst_pairs = list(user_and_dst_pairs)[:self.MAX_COMPROMISED_USERS]  # Limit to MAX_COMPROMISED_USERS pairs for performance
#         self.log(f"Candidate Hops: {len(user_and_dst_pairs)} candidate (user, dst) pairs")
#
#         return user_and_dst_pairs
#
#     def _update_candidate_dst(self, G, user):
#         if user in self.dst_per_compromised_user:
#             return
#
#         user_vertex = G.vs.find(name=f'user_{user}')
#         user_apps = G.neighbors(user_vertex, mode='out')
#         for app_index in user_apps:
#             app_vertex = G.vs[app_index]
#             app_resources = G.neighbors(app_vertex, mode='out')
#             for resource_index in app_resources:
#                 resource_vertex = G.vs[resource_index]
#                 self.dst_per_compromised_user[user].add(resource_vertex['name'])
#
#         self.log(f"Updating candidate dst with {len(self.dst_per_compromised_user[user])} dst for compromised user = {user}.")
#
# def generate_user_dst_pairs(dst_per_compromised_user):
#     for user, dsts in dst_per_compromised_user.items():
#         for dst in dsts:
#             yield (user, dst)
#
#
# # Example usage
# if __name__ == "__main__":
#     from attack_start import AttackStart
#     import pytz
#     from igraph import Graph
#
#     attacker_capabilities = AttackerCapabilities(knowledge='global')
#
#     # Test initialize_capabilities
#     start_state = AttackStart(start_src='app_A023', start_user='U004', start_time=datetime.datetime.now())
#
#     attacker_capabilities.initialize_capabilities(start_state, G)
#
#     print("Initialized Capabilities")
#     print(attacker_capabilities.dst_per_compromised_user)
#     # Expected Output: {'U001': {'resource_R001'}}
#
#     # Test update_capabilities
#     new_time = datetime.datetime(2022, 9, 21, 18, 59, 2, 409167, tzinfo=tz.tzutc())
#     new_dst = "resource_R002"
#     compromised_users = attacker_capabilities.update_capabilities(new_time, new_dst, G)
#     print("Updated Capabilities")
#     print(compromised_users)
#     print(attacker_capabilities.dst_per_compromised_user)
#     # Expected Output:
#     # Updated Capabilities
#     # {'U002'}
#     # {'U001': {'resource_R001'}, 'U002': {'resource_R001'}}
#
#     # Test get_candidate_next_hops
#     candidate_next_hops = attacker_capabilities.get_candidate_next_hops(AttackHistory(start_state))
#     print("Candidate Next Hops")
#     print(candidate_next_hops)
#     # Expected Output:
#     # Candidate Next Hops
#     # [AttackNextHop(appId='app_A001', resourceId='resource_R001', userId='U001'),
#     #  AttackNextHop(appId='app_A001', resourceId='resource_R001', userId='U002')]
from collections import defaultdict
from igraph import Graph
from datetime import datetime, timedelta
from dateutil import tz
from data_types import *
from utils import *
class AttackerCapabilities(LoggingClass):
    DEFAULT_CRED_EXPOSED_HRS = 24 * 7  # Default time window for exposed credentials (1 week)
    MAX_COMPROMISED_USERS = 50  # Maximum number of compromised users to process

    def __init__(self, knowledge, compromise_cred_hrs=None, verbose=True):
        super(AttackerCapabilities, self).__init__(verbose=verbose)
        self.knowledge = knowledge
        self.dst_per_compromised_user = defaultdict(set)
        self.real_users = get_all_users()

        self.compromise_cred_hrs = compromise_cred_hrs or self.DEFAULT_CRED_EXPOSED_HRS
        self.log(f"Attacker Capabilities set to: {self.knowledge}\tcred exposure window={self.compromise_cred_hrs} hrs\n")

    @classmethod
    def get_accessible_dst_for_user(cls, G, user):
        """
        Get all of the dst (resources) a user has access to.

        Args:
            G (ig.Graph): The graph object.
            user (str): The user ID.

        Returns:
            set: A set of accessible resource IDs.
        """
        user_vertex = G.vs.find(name=f'{user}')
        if not user_vertex:
            return set()

        # Get apps the user has accessed
        apps_accessed = set(G.neighbors(user_vertex, mode='out'))

        accessible_dst = set()
        for app_index in apps_accessed:
            connected_resources = set(G.neighbors(app_index, mode='out'))
            accessible_dst.update({G.vs[idx]["name"] for idx in connected_resources if G.vs[idx]["type"] == "resource"})

        return accessible_dst

    def initialize_capabilities(self, start_state, G):
        self._update_candidate_dst(G, start_state.start_user)

    def update_capabilities(self, new_time, new_dst, G):
        compromised_users = self._get_new_compromised_users(G, new_time, new_dst)
        for user in compromised_users:
            self._update_candidate_dst(G, user)
        return compromised_users

    def get_candidate_next_hops(self, attack_history, G):
        candidate_srcs = self._get_candidate_src(attack_history)
        self.log(f"Candidate Hops: Candidate src = {candidate_srcs}")

        next_hops = []
        for src in candidate_srcs:
            connected_resources = self._get_connected_resources(G, src)
            for user, dst in self._get_candidate_user_dst():
                if dst in connected_resources:
                    next_hops.append(AttackNextHop(appId=src, resourceId=dst, userId=user))

        self.log(f"Candidate Hops: {len(next_hops)} possible hops generated")
        return next_hops

    def _get_connected_resources(self, G, appId):
        if appId not in G.vs["name"]:
            return set()

        app_index = G.vs.find(name=appId).index
        connected_indices = set(G.neighbors(app_index, mode='out'))

        connected_resources = {G.vs[idx]["name"] for idx in connected_indices if G.vs[idx]["type"] == "resource"}
        return connected_resources

    def _get_candidate_src(self, attack_history):
        return attack_history.visited_dst

    def _get_candidate_user_dst(self):
        user_and_dst_pairs = generate_user_dst_pairs(self.dst_per_compromised_user)
        user_and_dst_pairs = list(user_and_dst_pairs)[:self.MAX_COMPROMISED_USERS]
        self.log(f"Candidate Hops: {len(user_and_dst_pairs)} candidate (user, dst) pairs")
        return user_and_dst_pairs

    def _get_new_compromised_users(self, G, time, host):
        lower_bound = time - timedelta(hours=self.compromise_cred_hrs)
        host_vertex = G.vs.find(name=host)
        if not host_vertex:
            return set()

        app_neighbors = G.neighbors(host_vertex, mode='in')
        vuln_users = set()

        for app_index in app_neighbors:
            app_vertex = G.vs[app_index]
            app_edges = G.es.select(_target=app_vertex.index)
            for edge in app_edges:
                if any(lower_bound <= t.replace(tzinfo=tz.tzutc()) <= time for t in edge['time']):
                    source_name = G.vs[edge.source]['name']
                    if source_name.startswith('user_'):
                        user = source_name.split('_')[1]
                        vuln_users.add(user)

        compromised_users = {u for u in vuln_users if u in self.real_users}
        return compromised_users

    def _update_candidate_dst(self, G, user):
        if user in self.dst_per_compromised_user:
            return

        user_vertex = G.vs.find(name=f'{user}')
        if not user_vertex:
            return

        user_apps = G.neighbors(user_vertex, mode='out')
        for app_index in user_apps:
            app_vertex = G.vs[app_index]
            app_resources = G.neighbors(app_vertex, mode='out')
            for resource_index in app_resources:
                resource_vertex = G.vs[resource_index]
                self.dst_per_compromised_user[user].add(resource_vertex['name'])

        self.log(f"Updating candidate dst with {len(self.dst_per_compromised_user[user])} dst for compromised user = {user}.")

# class AttackerCapabilities(LoggingClass):
#     DEFAULT_CRED_EXPOSED_HRS = 24 * 7  # Default time window for exposed credentials (1 week)
#     MAX_COMPROMISED_USERS = 50  # Maximum number of compromised users to process
#
#     def __init__(self, knowledge, compromise_cred_hrs=None, verbose=True):
#         super(AttackerCapabilities, self).__init__(verbose=verbose)
#         self.knowledge = knowledge
#         self.dst_per_compromised_user = defaultdict(set)
#         self.real_users = get_all_users()
#
#         self.compromise_cred_hrs = compromise_cred_hrs or self.DEFAULT_CRED_EXPOSED_HRS
#         self.log(f"Attacker Capabilities set to: {self.knowledge}\tcred exposure window={self.compromise_cred_hrs} hrs\n")
#
#     @classmethod
#     def get_accessible_dst_for_user(cls, G, user):
#         """
#         Get all of the dst (resources) a user has access to.
#
#         Args:
#             G (ig.Graph): The graph object.
#             user (str): The user ID.
#
#         Returns:
#             set: A set of accessible resource IDs.
#         """
#         user_vertex = G.vs.find(name=f'user_{user}')
#         if not user_vertex:
#             return set()
#
#         # Get apps the user has accessed
#         apps_accessed = set(G.neighbors(user_vertex, mode='out'))
#
#         accessible_dst = set()
#         for app_index in apps_accessed:
#             connected_resources = set(G.neighbors(app_index, mode='out'))
#             accessible_dst.update({G.vs[idx]["name"] for idx in connected_resources if G.vs[idx]["type"] == "resource"})
#
#         return accessible_dst
#                 # - UNINTERESTING_DST)
#
#     def initialize_capabilities(self, start_state, G):
#         """
#         Initialize capabilities based on the starting state.
#
#         Args:
#             start_state (State): The initial state of the attack.
#             G (ig.Graph): The graph object.
#         """
#         self._update_candidate_dst(G, start_state.start_user)
#
#     def update_capabilities(self, new_time, new_dst, G):
#         """
#         Update capability set: compromised cred set + dest set.
#
#         Args:
#             new_time (datetime): The current time in the attack.
#             new_dst (str): The new destination (resource) being accessed.
#             G (ig.Graph): The graph object.
#
#         Returns:
#             set: A set of compromised user IDs.
#         """
#         compromised_users = self._get_new_compromised_users(G, new_time, new_dst)
#         for user in compromised_users:
#             self._update_candidate_dst(G, user)
#
#         return compromised_users
#
#     def get_candidate_next_hops(self, attack_history, G):
#         """
#         Generate all possible movement hops.
#
#         Args:
#             attack_history (AttackHistory): Object tracking the attack's progress.
#             G (ig.Graph): The graph object.
#
#         Returns:
#             list: A list of AttackNextHop namedtuple's.
#         """
#         candidate_srcs = self._get_candidate_src(attack_history)
#         self.log(f"Candidate Hops: Candidate src = {candidate_srcs}")
#
#         next_hops = []
#         for src in candidate_srcs:
#             connected_resources = self._get_connected_resources(G, src)
#             for user, dst in self._get_candidate_user_dst():
#                 if dst in connected_resources:
#                     next_hops.append(AttackNextHop(appId=src, resourceId=dst, userId=user))
#
#         self.log(f"Candidate Hops: {len(next_hops)} possible hops generated")
#         return next_hops
#
#     def _get_connected_resources(self, G, appId):
#         """
#         Get all resources connected to the given app.
#
#         Parameters:
#         - G (ig.Graph): The graph object.
#         - appId (str): The app ID.
#
#         Returns:
#         - connected_resources (set): A set of connected resource IDs.
#         """
#         if appId not in G.vs["name"]:
#             return set()
#
#         app_index = G.vs.find(name=appId).index
#         connected_indices = set(G.neighbors(app_index, mode='out'))
#
#         connected_resources = {G.vs[idx]["name"] for idx in connected_indices if G.vs[idx]["type"] == "resource"}
#
#         return connected_resources
#
#     def _get_candidate_src(self, attack_history):
#         """
#         Get candidate src of next hops = all visited machines.
#
#         Args:
#             attack_history (AttackHistory): Object tracking the attack's progress.
#
#         Returns:
#             set: A set of candidate source IDs.
#         """
#         return attack_history.visited_dst
#
#     def _get_candidate_user_dst(self):
#         """
#         Get accessible pairs of (user, dst) moves.
#
#         Returns:
#             list: A list of tuples representing user and destination pairs.
#         """
#         user_and_dst_pairs = generate_user_dst_pairs(self.dst_per_compromised_user)
#         user_and_dst_pairs = list(user_and_dst_pairs)[:self.MAX_COMPROMISED_USERS]  # Limit to MAX_COMPROMISED_USERS pairs for performance
#         self.log(f"Candidate Hops: {len(user_and_dst_pairs)} candidate (user, dst) pairs")
#
#         return user_and_dst_pairs
#
#     def _get_new_compromised_users(self, G, time, host):
#         """
#         Simulate an attacker compromising creds on a host.
#
#         Args:
#             G (ig.Graph): The graph object.
#             time (datetime): The current time.
#             host (str): The compromised host.
#
#         Returns:
#             set: A set of compromised user IDs.
#         """
#         # if host in NON_COMPROMISE_HOSTS or not is_compromisable_host(host):
#         #     self.log(f"Host = {host} is non-compromise-able, so skipping cred compromise")
#         #     return set()
#
#         lower_bound = time - timedelta(hours=self.compromise_cred_hrs)
#         host_vertex = G.vs.find(name=host)
#         if not host_vertex:
#             return set()
#
#         app_neighbors = G.neighbors(host_vertex, mode='in')
#         vuln_users = set()
#
#         for app_index in app_neighbors:
#             app_vertex = G.vs[app_index]
#             app_edges = G.es.select(_target=app_vertex.index)
#             for edge in app_edges:
#                 if any(lower_bound <= t.replace(tzinfo=tz.tzutc()) <= time for t in edge['time']):
#                     source_name = G.vs[edge.source]['name']
#                     if source_name.startswith('user_'):
#                         user = source_name.split('_')[1]
#                         vuln_users.add(user)
#
#         compromised_users = {u for u in vuln_users if u in self.real_users}
#         return compromised_users
#
#     def _update_candidate_dst(self, G, user):
#         """
#         Update set of available destinations attacker can move to.
#
#         Args:
#             G (ig.Graph): The graph object.
#             user (str): The compromised user ID.
#         """
#         if user in self.dst_per_compromised_user:
#             return
#
#         user_vertex = G.vs.find(name=f'user_{user}')
#         if not user_vertex:
#             return
#
#         user_apps = G.neighbors(user_vertex, mode='out')
#         for app_index in user_apps:
#             app_vertex = G.vs[app_index]
#             app_resources = G.neighbors(app_vertex, mode='out')
#             for resource_index in app_resources:
#                 resource_vertex = G.vs[resource_index]
#                 self.dst_per_compromised_user[user].add(resource_vertex['name'])
#
#         self.log(f"Updating candidate dst with {len(self.dst_per_compromised_user[user])} dst for compromised user = {user}.")

def generate_user_dst_pairs(dst_per_compromised_user):
    for user, dsts in dst_per_compromised_user.items():
        for dst in dsts:
            yield (user, dst)
if __name__ == "__main__":
    from attack_start import AttackStart
    from data_types import AttackHistory
    from igraph import Graph
    import datetime
    from dateutil import tz
    # Initialize AttackerCapabilities
    attacker_capabilities = AttackerCapabilities(knowledge='local')

    # Initialize AttackStart and AttackHistory
    start_state = AttackStart(start_src='app_A023', start_user='U004', start_time=datetime.datetime.now())
    attack_history = AttackHistory(start_state=start_state,login_graph=G)

    # Test initialize_capabilities
    attacker_capabilities.initialize_capabilities(start_state, G)
    print("Initialized Capabilities")
    print(attacker_capabilities.dst_per_compromised_user)
    # Expected Output: {'U004': {'resource_R001', 'resource_R002'}}

    # Test update_capabilities
    new_time = datetime.datetime(2022, 9, 21, 18, 59, 2, 409167, tzinfo=tz.tzutc())
    new_dst = "resource_R002"
    compromised_users = attacker_capabilities.update_capabilities(new_time, new_dst, G)
    print("Updated Capabilities")
    print(compromised_users)
    print(attacker_capabilities.dst_per_compromised_user)
    # Expected Output:
    # Updated Capabilities
    # {'U004'}
    # {'U004': {'resource_R001', 'resource_R002'}}

    # Test get_candidate_next_hops
    candidate_next_hops = attacker_capabilities.get_candidate_next_hops(G=G,attack_history=attack_history)
    print("Candidate Next Hops")
    print(candidate_next_hops)
    # Expected Output:
    # Candidate Next Hops
    # [AttackNextHop(appId='app_A023', resourceId='resource_R001', userId='U004'),
    #  AttackNextHop(appId='app_A023', resourceId='resource_R002', userId='U004')]