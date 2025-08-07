from data_types import *
from utils import *
from collections import defaultdict
class MovementGoal(LoggingClass):
    MAX_HOPS = 50
    GOAL_EXPLORATION = ScenarioConstants.GOAL_EXPLORATION
    GOAL_SPREAD = ScenarioConstants.GOAL_SPREAD
    GOAL_TARGETED = ScenarioConstants.GOAL_TARGETED

    def __init__(self, goal, target_machines=set(), verbose=True):
        super(MovementGoal, self).__init__(verbose=verbose)
        self.goal = goal
        self.target_info = TargetingInfo(target_machines)
        self.compromised_priv_users = set()
        self.current_path = None
        self.current_path_index = 0
        self.visited_apps = set()  # To track apps visited during the spread goal
        self.log(f"Attack Goal = {self.goal}\tTarget machines = {target_machines}\n")

    def heuristic_targeted(self, hop, attack_history):
        if hop.resourceId in self.target_info.target_machines:
            return 0  # Highest priority
        if self.target_info.next_hop_go_to_target_dsts(hop.resourceId):
            return 1
        return 2

    def heuristic_spread(self, hop, attack_history):
        if hop.appId not in self.visited_apps:
            return 0  # Highest priority for unvisited apps
        if hop.resourceId not in attack_history.visited_dst:
            return 0  # Next priority for unvisited resources
        return 1  # Lower priority for already visited nodes

    def heuristic_exploration(self, hop, attack_history):
        if hop.resourceId not in attack_history.visited_dst:
            return 0  # Highest priority for unvisited resources
        return 1  # Lower priority for already visited nodes

    def heuristic_uncommon(self, hop, attack_history):
        edge_weight = self.target_info.get_edge_weight(hop.appId, hop.resourceId)
        return edge_weight  # Lower weight means less common, thus higher priority

    def select_next_hop(self, candidate_next_hops, attack_history, attack_capabilities):
        self.log(f"Next hop (Goal): Selecting next hop from {len(candidate_next_hops)} candidate hops.\n")

        if self.goal == self.GOAL_TARGETED:
            candidate_next_hops = sorted(candidate_next_hops, key=lambda hop: self.heuristic_targeted(hop, attack_history))
        elif self.goal == self.GOAL_SPREAD:
            candidate_next_hops = sorted(candidate_next_hops, key=lambda hop: self.heuristic_spread(hop, attack_history))
        elif self.goal == self.GOAL_EXPLORATION:
            candidate_next_hops = sorted(candidate_next_hops, key=lambda hop: self.heuristic_exploration(hop, attack_history))
        else:
            candidate_next_hops = sorted(candidate_next_hops, key=lambda hop: self.heuristic_uncommon(hop, attack_history))

        if len(candidate_next_hops) > 0:
            # Try to pivot to another user if possible
            for hop in candidate_next_hops:
                next_hop_user = attack_history.pivot_to_user(hop.appId)
                if next_hop_user:
                    self.log(f"Pivoting to user {next_hop_user} via app {hop.appId}.")
                    hop = AttackNextHop(hop.appId, hop.resourceId, next_hop_user)

        max_candidates = 1000
        if len(candidate_next_hops) > max_candidates:
            candidate_next_hops = candidate_next_hops[:max_candidates]
            self.log(f"Limiting candidate hops to {max_candidates} for performance reasons.\n")

        preferred_hops = [
            hop for hop in candidate_next_hops if (
                hop.appId == attack_history.get_current_machine() or
                hop.appId == attack_history.get_start_src()
            )
        ]
        if len(preferred_hops) > 0:
            candidate_next_hops = preferred_hops

        self.log(f"Next hop (Goal): {len(candidate_next_hops)} candidate next hops based on goal = {self.goal}.\n")

        next_hop = safe_rand_sample(candidate_next_hops, 1)
        if next_hop and len(next_hop) == 1:
            if self.goal == self.GOAL_SPREAD:
                self.visited_apps.add(next_hop[0].appId)  # Mark the app as visited for the spread goal
            return next_hop[0]

        return AttackNextHop(None, None, None)

    def is_attack_complete(self, attack_history):
        if attack_history is None:
            return False
        elif attack_history.num_hops > self.MAX_HOPS:
            self.log(f"\nWARNING: Terminating attack because movement exceeds max hop limit of {self.MAX_HOPS}.\n")
            return True

        if self.goal == self.GOAL_EXPLORATION:
            return attack_history.num_hops > 1 and (
                attack_history.get_start_user() != attack_history.get_current_user())
        elif self.goal == self.GOAL_SPREAD:
            return attack_history.num_hops > self.MAX_HOPS
        elif self.goal == self.GOAL_TARGETED and self.target_info.initialized and len(self.target_info.paths_to_priv_users) == 0:
            self.log(
                f"\nWARNING: Terminating attack because NO viable path exists to a machine with exposed priv users = {self.target_info.priv_users} from src = {attack_history.get_start_src()}\n")
            return True
        else:
            return attack_history.cur_machine in self.target_info.target_machines

    def update_progress(self, new_dst, compromised_users):
        self.compromised_priv_users = compromised_users.intersection(self.target_info.priv_users)

# class MovementGoal(LoggingClass):
#     MAX_HOPS = 50
#     GOAL_EXPLORATION = ScenarioConstants.GOAL_EXPLORATION
#     GOAL_SPREAD = ScenarioConstants.GOAL_SPREAD
#     GOAL_TARGETED = ScenarioConstants.GOAL_TARGETED
#
#     def __init__(self, goal, target_machines=set(), verbose=True):
#         super(MovementGoal, self).__init__(verbose=verbose)
#         self.goal = goal
#         self.target_info = TargetingInfo(target_machines)
#         self.compromised_priv_users = set()
#         self.current_path = None
#         self.current_path_index = 0
#         self.log(f"Attack Goal = {self.goal}\tTarget machines = {target_machines}\n")
#
#     def heuristic_targeted(self, hop, attack_history):
#         print(hop)
#         if hop.resourceId in self.target_info.target_machines:
#             return 0  # Highest priority
#         if self.target_info.next_hop_go_to_target_dsts(hop.resourceId):
#             return 1
#         return 2
#
#     def heuristic_spread(self, hop, attack_history):
#         if hop.dst not in attack_history.visited_dst:
#             return 0  # Highest priority
#         return 1
#
#     def heuristic_exploration(self, hop, attack_history):
#         if hop.dst not in attack_history.visited_dst:
#             return 0  # Highest priority
#         return 1
#
#     def heuristic_uncommon(self, hop, attack_history):
#         edge_weight = self.target_info.get_edge_weight(hop.src, hop.dst)
#         return edge_weight  # Lower weight means less common, thus higher priority
#
#     def select_next_hop(self, candidate_next_hops, attack_history, attack_capabilities):
#         self.log(f"Next hop (Goal): Selecting next hop from {len(candidate_next_hops)} candidate hops.\n")
#
#         if self.goal == self.GOAL_TARGETED:
#             candidate_next_hops = sorted(candidate_next_hops,
#                                          key=lambda hop: self.heuristic_targeted(hop, attack_history))
#         elif self.goal == self.GOAL_SPREAD:
#             candidate_next_hops = sorted(candidate_next_hops,
#                                          key=lambda hop: self.heuristic_spread(hop, attack_history))
#         elif self.goal == self.GOAL_EXPLORATION:
#             candidate_next_hops = sorted(candidate_next_hops,
#                                          key=lambda hop: self.heuristic_exploration(hop, attack_history))
#         else:
#             candidate_next_hops = sorted(candidate_next_hops,
#                                          key=lambda hop: self.heuristic_uncommon(hop, attack_history))
#
#         if len(candidate_next_hops) > 0:
#             # Try to pivot to another user if possible
#             for hop in candidate_next_hops:
#                 next_hop_user = attack_history.pivot_to_user(hop.appId)
#                 if next_hop_user:
#                     self.log(f"Pivoting to user {next_hop_user} via app {hop.appId}.")
#                     hop = AttackNextHop(hop.appId, hop.resourceId, next_hop_user)
#
#         max_candidates = 1000
#         if len(candidate_next_hops) > max_candidates:
#             candidate_next_hops = candidate_next_hops[:max_candidates]
#             self.log(f"Limiting candidate hops to {max_candidates} for performance reasons.\n")
#
#         preferred_hops = [
#             hop for hop in candidate_next_hops if (
#                     hop.appId == attack_history.get_current_machine() or
#                     hop.appId == attack_history.get_start_src()
#             )
#         ]
#         if len(preferred_hops) > 0:
#             candidate_next_hops = preferred_hops
#
#         self.log(f"Next hop (Goal): {len(candidate_next_hops)} candidate next hops based on goal = {self.goal}.\n")
#
#         next_hop = safe_rand_sample(candidate_next_hops, 1)
#         if next_hop and len(next_hop) == 1:
#             return next_hop[0]
#
#         return AttackNextHop(None, None, None)
#
#     def is_attack_complete(self, attack_history):
#         if attack_history is None:
#             return False
#         elif attack_history.num_hops > self.MAX_HOPS:
#             self.log(f"\nWARNING: Terminating attack because movement exceeds max hop limit of {self.MAX_HOPS}.\n")
#             return True
#
#         if self.goal == self.GOAL_EXPLORATION:
#             return attack_history.num_hops > 1 and (
#                         attack_history.get_start_user() != attack_history.get_current_user())
#         elif self.goal == self.GOAL_SPREAD:
#             return attack_history.num_hops > self.MAX_HOPS
#         elif self.goal == self.GOAL_TARGETED and self.target_info.initialized and len(
#                 self.target_info.paths_to_priv_users) == 0:
#             self.log(
#                 f"\nWARNING: Terminating attack because NO viable path exists to a machine with exposed priv users = {self.target_info.priv_users} from src = {attack_history.get_start_src()}\n")
#             return True
#         else:
#             return attack_history.cur_machine in self.target_info.target_machines
#
#     def update_progress(self, new_dst, compromised_users):
#         self.compromised_priv_users = compromised_users.intersection(self.target_info.priv_users)


class TargetingInfo(LoggingClass):
    MAX_PATH_LEN = 10

    def __init__(self, target_machines, verbose=True):
        super(TargetingInfo, self).__init__(verbose=verbose)
        self.initialized = False
        self.target_machines = target_machines
        self.start_user = None
        self.login_graph = None
        self.priv_users = set()
        self.paths_to_priv_users = []
        self.paths_to_targets = []
        self.nodes_to_priv_users = set()
        self.nodes_to_targets = set()

    def initialize(self, G, start_src, start_time):
        """Compute data structures."""
        self.log(
            f"\nTargetingInfo: Precomputing paths to viable creds & target dst:\t"
            f"start: {start_src} to dsts = {self.target_machines}.\n"
        )
        self.login_graph = G
        self.priv_users = self.get_priv_users(G, self.target_machines)  # Pass G and target_machines
        self.paths_to_priv_users = self.get_paths_to_priv_users(G, self.priv_users, self.target_machines)
        self.nodes_to_priv_users = set(flatten_list(self.paths_to_priv_users))
        self.nodes_to_targets = set(flatten_list(self.paths_to_targets))
        self.initialized = True

        self.log(f"Ten paths to privileged users: {safe_rand_sample(self.paths_to_priv_users,10)}")
        self.log(f"Ten paths to target machines: {safe_rand_sample(self.paths_to_targets,10)}")

    def next_hop_go_to_priv_users(self, next_dst):
        return next_dst in self.nodes_to_priv_users

    def next_hop_go_to_target_dsts(self, next_dst):
        return next_dst in self.nodes_to_targets or next_dst in self.target_machines

    def get_edge_weight(self, src, dst):
        """Get the weight of an edge in the graph."""
        src_idx = self.login_graph.vs.find(name=src).index
        dst_idx = self.login_graph.vs.find(name=dst).index
        edge_id = self.login_graph.get_eid(src_idx, dst_idx)
        return self.login_graph.es[edge_id]['weight']

    @classmethod
    def get_priv_users(cls, G, target_machines):
        """
        Get set of users / credentials who can access target machines by:
        1. Finding apps connected to the target machines.
        2. Retrieving all users connected to those apps.

        Args:
            G (igraph.Graph): The graph object.
            target_machines (set): Set of target machine (resource) names.

        Returns:
            set: A set of privileged user nodes who have access to the target machines.
        """
        # Step 1: Identify apps connected to the target machines (resources)
        target_vertices = [v.index for v in G.vs if v['name'] in target_machines and v['type'] == 'resource']
        connected_apps = set()
        for vertex in target_vertices:
            app_neighbors = G.neighbors(vertex, mode="in")  # Find apps connected to the target machines
            connected_apps.update(
                [G.vs[neighbor]['name'] for neighbor in app_neighbors if G.vs[neighbor]['type'] == 'app'])

        # Step 2: Identify users connected to the identified apps
        priv_users = set()
        for app in connected_apps:
            app_index = G.vs.find(name=app).index
            user_neighbors = G.neighbors(app_index, mode="in")  # Find users connected to these apps
            priv_users.update(
                [G.vs[neighbor]['name'] for neighbor in user_neighbors if G.vs[neighbor]['type'] == 'user'])

        return priv_users

    @classmethod
    def get_paths_to_priv_users(cls, G, priv_users, target_machines):
        """
        Get all paths from privileged users to target machines (resources).

        Args:
            G (igraph.Graph): The graph object.
            priv_users (set): Set of privileged user nodes.
            target_machines (set): Set of target machine (resource) names.

        Returns:
            list: A list of paths from privileged users to target machines.
        """
        # Step 1: Identify the indices of the target machines in the graph
        target_indices = [G.vs.find(name=target).index for target in target_machines if G.vs.find(name=target)]

        # Step 2: Initialize an empty list to hold all the paths
        all_paths = []

        # Step 3: For each privileged user, find paths to the target machines
        for user in priv_users:
            user_index = G.vs.find(name=user).index
            for target_index in target_indices:
                # Find all simple paths from the privileged user to the target machine
                paths = G.get_all_simple_paths(user_index, to=target_index, mode="out")
                # Ensure that the paths reach the target machines (not just intermediary apps)
                for path in paths:
                    if len(path) - 1 <= cls.MAX_PATH_LEN:
                        all_paths.append(path)

        print(
            f"Computed {len(all_paths)} paths of length <= {cls.MAX_PATH_LEN}.\nSample paths: {safe_rand_sample(all_paths, 3)}")
        return all_paths



if __name__ == "__main__":
    from igraph import Graph
    import datetime
    from attack_start import AttackStart
    from data_types import LoginColumns,AttackHistory
    from utils import safe_rand_sample
    from attack_capabilities import AttackerCapabilities
    attacker_capabilities = AttackerCapabilities(knowledge='global')

    # Initialize TargetingInfo
    target_machines = {'resource_R005'}
    targeting_info = TargetingInfo(target_machines)
    targeting_info.initialize(G, start_src='app_A001', start_time=datetime.datetime.now())
    print("Initialized TargetingInfo")
    print("Paths to Privileged Users:", targeting_info.paths_to_priv_users)
    print("Paths to Target Machines:", targeting_info.paths_to_targets)
    # Expected Output: Lists of paths to privileged users and target machines.

    # Initialize MovementGoal
    movement_goal = MovementGoal(goal=MovementGoal.GOAL_TARGETED, target_machines=target_machines)

    # Initialize AttackStart and AttackHistory
    start_state = AttackStart(start_src='app_A001', start_user='U001', start_time=datetime.datetime.now())
    attack_history = AttackHistory(start_state=start_state,login_graph=G)

    attacker_capabilities.initialize_capabilities(start_state, G)

    # Test select_next_hop
    candidate_hops = attacker_capabilities.get_candidate_next_hops(G=G,attack_history=attack_history)
    next_hop = movement_goal.select_next_hop(candidate_hops, attack_history, None)
    print("Selected Next Hop:", next_hop)
    # Expected Output: The next hop selected based on the targeted goal.

    # Test is_attack_complete
    attack_complete = movement_goal.is_attack_complete(attack_history)
    print("Is Attack Complete?", attack_complete)
    # Expected Output: False initially, as the attack should not be complete.

    # Test update_progress
    movement_goal.update_progress('resource_R002', {'U001'})
    print("Updated Compromised Privileged Users:", movement_goal.compromised_priv_users)
    # Expected Output: {'U001'} if U001 is a privileged user.

    # Initialize MovementGoal for Spread
    movement_goal_spread = MovementGoal(goal=MovementGoal.GOAL_SPREAD)

    # Initialize AttackStart and AttackHistory
    start_state_spread = AttackStart(start_src='app_A001', start_user='U001', start_time=datetime.datetime.now())
    attack_history_spread = AttackHistory(start_state=start_state_spread, login_graph=G)

    attacker_capabilities.initialize_capabilities(start_state_spread, G)

    # Test select_next_hop for Spread Goal
    candidate_hops_spread = attacker_capabilities.get_candidate_next_hops(G=G, attack_history=attack_history_spread)
    next_hop_spread = movement_goal_spread.select_next_hop(candidate_hops_spread, attack_history_spread, None)
    print("Selected Next Hop for Spread Goal:", next_hop_spread)
    # Expected Output: The next hop selected based on the spread goal, prioritizing unvisited apps and resources.

    # Test is_attack_complete for Spread Goal
    attack_complete_spread = movement_goal_spread.is_attack_complete(attack_history_spread)
    print("Is Attack Complete for Spread Goal?", attack_complete_spread)
    # Expected Output: False initially, as the attack should not be complete until all apps and resources are accessed.

    # Test update_progress for Spread Goal
    movement_goal_spread.update_progress('resource_R002', {'U001'})
    print("Updated Compromised Privileged Users for Spread Goal:", movement_goal_spread.compromised_priv_users)
    # Expected Output: {'U001'} if U001 is a privileged user.
    # Initialize MovementGoal for Exploration
    movement_goal_exploration = MovementGoal(goal=MovementGoal.GOAL_EXPLORATION)

    # Initialize AttackStart and AttackHistory
    start_state_exploration = AttackStart(start_src='app_A001', start_user='U001', start_time=datetime.datetime.now())
    attack_history_exploration = AttackHistory(start_state=start_state_exploration, login_graph=G)

    attacker_capabilities.initialize_capabilities(start_state_exploration, G)

    # Test select_next_hop for Exploration Goal
    candidate_hops_exploration = attacker_capabilities.get_candidate_next_hops(G=G, attack_history=attack_history_exploration)
    next_hop_exploration = movement_goal_exploration.select_next_hop(candidate_hops_exploration, attack_history_exploration, None)
    print("Selected Next Hop for Exploration Goal:", next_hop_exploration)
    # Expected Output: The next hop selected based on the exploration goal, prioritizing new, unvisited resources.

    # Test is_attack_complete for Exploration Goal
    attack_complete_exploration = movement_goal_exploration.is_attack_complete(attack_history_exploration)
    print("Is Attack Complete for Exploration Goal?", attack_complete_exploration)
    # Expected Output: False initially, as the attack should not be complete until a dead end is reached.

    # Test update_progress for Exploration Goal
    movement_goal_exploration.update_progress('resource_R002', {'U001'})
    print("Updated Compromised Privileged Users for Exploration Goal:", movement_goal_exploration.compromised_priv_users)
    # Expected Output: {'U001'} if U001 is a privileged user.

