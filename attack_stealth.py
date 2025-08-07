# from data_types import *
# from utils import *
# from datetime import timedelta
#
# class MovementConstraints(LoggingClass):
#     """Define constraints + pruning over movement paths."""
#     SRC_PREF_NONE = "src_pref=none"
#     SRC_PREF_FOOTHOLD = "src_pref=foothold"
#     SRC_PREF_SERVER = "src_pref=server"
#     SRC_PREF_CRED_SWITCH_AT_SERVER = "src_pref=cred-switch-at-server"
#
#     MANAGEMENT_MACHINE = '-'  # machines to ignore during attack generation
#     def __init__(self, src_preference=None, verbose=True):
#         super(MovementConstraints, self).__init__(verbose=verbose)
#         self.src_preference = src_preference
#         if self.src_preference is None:
#             self.src_preference = self.SRC_PREF_NONE
#
#     def constrain_next_hops(self, G, next_hops, attack_history):
#         next_hops = self._remove_invalid_user_dst_hops(G, next_hops, attack_history)
#         next_hops = self._handle_jump_host_src(next_hops, attack_history)
#         next_hops = self._apply_src_preference(next_hops, attack_history)
#         return next_hops
#
#     def _remove_invalid_user_dst_hops(self, G, next_hops, attack_history):
#         start_user = attack_history.get_start_user()
#         accessible_dst_from_start = attack_history.get_start_accessible_dst()
#         next_hops = [
#             hop for hop in next_hops if not(
#                 hop.userId != start_user and hop.resourceId in accessible_dst_from_start
#             )
#         ]
#
#         next_hops = [
#             hop for hop in next_hops if not(
#                 is_server_jump_host(hop.resourceId) and hop.userId != start_user
#             )
#         ]
#
#         self.log("Path Constraints: {} hops after removing invalid user-dst's".format(len(next_hops)))
#         return next_hops
#
#     def _handle_jump_host_src(self, next_hops, attack_history):
#         cur_machine = attack_history.get_current_machine()
#         self.log("Path Constraints: currently on host = {}. Pruning any potential bastion paths accordingly.".format(cur_machine))
#         if is_server_jump_host(cur_machine):
#             next_hops = [
#                 hop for hop in next_hops if (
#                     hop.appId == cur_machine and
#                     hop.userId == attack_history.get_current_user()
#                 )
#             ]
#             self.log("Path Constraints: currently on a jump host = {}, so restricting to {} hops from bastion w/ continuity.".format(cur_machine, len(next_hops)))
#         else:
#             next_hops = [
#                 hop for hop in next_hops if not is_server_jump_host(hop.appId)
#             ]
#             self.log("Path Constraints: {} hops after removing any that start from a bastion (since NOT on bastion).".format(len(next_hops)))
#         return next_hops
#
#     def _apply_src_preference(self, next_hops, attack_history):
#         foothold = attack_history.get_start_src()
#         cur_machine = attack_history.get_current_machine()
#         cur_user = attack_history.get_current_user()
#
#         if self.src_preference == self.SRC_PREF_FOOTHOLD:
#             next_hops = [hop for hop in next_hops if hop.appId == foothold]
#             return next_hops
#
#         if self.src_preference == self.SRC_PREF_SERVER:
#             next_hops = [
#                 hop for hop in next_hops if (
#                     hop.userId == cur_user or hop.appId != foothold
#                 )]
#         elif self.src_preference == self.SRC_PREF_CRED_SWITCH_AT_SERVER:
#             next_hops = [
#                 hop for hop in next_hops if (
#                     hop.userId == cur_user or
#                     (hop.userId != cur_user and hop.appId != foothold)
#                 )]
#
#         next_hops = [
#             hop for hop in next_hops if (
#                 hop.userId == cur_user or
#                 hop.userId in attack_history.compromised_creds_per_dst.get(hop.appId, [])
#             )
#         ]
#
#         return next_hops
#
# class MovementStealth(MovementConstraints):
#     """Define movement's stealthiness and next hop pruning."""
#     # related to particular detector: time window to confuse our path inference engine
#     ACTIVE_CRED_HRS = 24
#     # the length of prior history where an attacker can see what logins have
#     # prev been made from a src machine (for stealthy edge movement)
#     DEFAULT_SRC_HISTORY_HRS = 24 * 31
#
#     STEALTH_NONE = ScenarioConstants.STEALTH_NONE
#     STEALTH_ENDPOINTS = ScenarioConstants.STEALTH_ENDPOINTS
#     STEALTH_ACTIVE_CREDS = ScenarioConstants.STEALTH_ACTIVE_CREDS
#     STEALTH_FULL = ScenarioConstants.STEALTH_FULL
#     def __init__(self, stealth, active_cred_hrs=None, src_history_hrs=None, src_pref=MovementConstraints.SRC_PREF_NONE, verbose=True):
#         super(MovementStealth, self).__init__(src_preference=src_pref, verbose=verbose)
#         self.stealth = stealth
#
#         self.last_time_src_dst = dict()
#         self.last_time_src_dst_user = dict()
#         self.src_history_hrs = src_history_hrs
#         if not self.src_history_hrs:
#             self.src_history_hrs = self.DEFAULT_SRC_HISTORY_HRS
#
#         self.last_active_machine_user = dict()
#         self.active_cred_hrs = active_cred_hrs
#         if not self.active_cred_hrs:
#             self.active_cred_hrs = self.ACTIVE_CRED_HRS
#
#         self.log("Movement Stealthiness: {}\tactive cred window={} hrs\tsrc preference = {}\n".format(self.stealth, self.active_cred_hrs, src_pref))
#
#     def constrain_next_hops(self, G, next_hops, attack_history):
#         print("Attack Stealthiness: {} candidate hops prior to constraints".format(len(next_hops)))
#         next_hops = self._remove_visited_dst(next_hops, attack_history)
#
#         if self.stealth in [self.STEALTH_ACTIVE_CREDS, self.STEALTH_FULL]:
#             next_hops = self._constraint_to_active_user_on_src(G, next_hops, attack_history)
#
#         if self.stealth in [self.STEALTH_ENDPOINTS, self.STEALTH_FULL]:
#             next_hops = self._constraint_to_prev_src_dst(next_hops, attack_history)
#
#         return next_hops
#
#     def update_knowledge(self, G, new_time, new_dst):
#         """Update stealthiness state / environment knowledge.
#
#         Args:
#             G: igraph.Graph object
#             new_time: datetime.datetime object
#             new_dst: str (hostname)
#         """
#         self._update_active_compromised_creds(G, new_time, new_dst)
#         self._update_src_dst_recent_history(G, new_time, new_dst)
#
#     def _remove_visited_dst(self, next_hops, attack_history):
#         print(next_hops)
#         next_hops = [
#             hop for hop in next_hops if hop.resourceId not in attack_history.get_visited_dst()
#         ]
#         self.log("Attack Stealthiness: {} candidate hops after removing visited dst".format(len(next_hops)))
#         return next_hops
#
#     def _update_src_dst_recent_history(self, G, move_time, new_dst):
#         """HELPER Method: Get history of where this new dst machine has launched logins into."""
#         min_time = move_time - timedelta(hours=self.src_history_hrs)
#
#         recent_logins = G.es.select(_source=G.vs.find(name=new_dst).index, time_ge=min_time, time_le=move_time)
#         last_time_per_src_dst = {}
#         for edge in recent_logins:
#             src_dst_key = (G.vs[edge.source]['name'], G.vs[edge.target]['name'])
#             if src_dst_key not in last_time_per_src_dst:
#                 last_time_per_src_dst[src_dst_key] = max(edge['time'])
#             else:
#                 last_time_per_src_dst[src_dst_key] = max(last_time_per_src_dst[src_dst_key], max(edge['time']))
#
#         self.last_time_src_dst.update(last_time_per_src_dst)
#         self.log("Attack Stealthiness (update): new_dst = {} has recently launched "
#                  "logins into {} subsequent dst machines".format(
#             new_dst, len(last_time_per_src_dst)
#         ))
#
#         last_time_per_src_dst_user = {}
#         for edge in recent_logins:
#             src_dst_user_key = (G.vs[edge.source]['name'], G.vs[edge.target]['name'], edge['user'])
#             if src_dst_user_key not in last_time_per_src_dst_user:
#                 last_time_per_src_dst_user[src_dst_user_key] = max(edge['time'])
#             else:
#                 last_time_per_src_dst_user[src_dst_user_key] = max(last_time_per_src_dst_user[src_dst_user_key],
#                                                                    max(edge['time']))
#
#         self.last_time_src_dst_user.update(last_time_per_src_dst_user)
#
#     def _constraint_to_prev_src_dst(self, next_hops, attack_history):
#         min_active_time = attack_history.last_move_time - timedelta(hours=self.src_history_hrs)
#         next_hops = [
#             hop for hop in next_hops if (
#                 self.last_time_src_dst.get((hop.appId, hop.resourceId)) is not None and
#                 self.last_time_src_dst.get((hop.appId, hop.resourceId)) >= min_active_time
#             )
#         ]
#         self.log("Attack Stealthiness: {} next hops that traverse a prev successful src - dst edge (past {} hrs).".format(len(next_hops), self.src_history_hrs))
#
#         max_stealth_next_hops = [
#             hop for hop in next_hops if (
#                 self.last_time_src_dst_user.get((hop.appId, hop.resourceId, hop.userId)) is not None and
#                 self.last_time_src_dst_user.get((hop.appId, hop.resourceId, hop.userId)) >= min_active_time
#             )
#         ]
#         if len(max_stealth_next_hops) > 0:
#             next_hops = max_stealth_next_hops
#             self.log("Attack Stealthiness: {} next hops that traverse a prev successful FULL <src, dst, user> edge (past {} hrs).".format(len(next_hops), self.src_history_hrs))
#
#         return next_hops
#
#     def _update_active_compromised_creds(self, G, move_time, new_dst):
#         """HELPER Method: What credentials are active on a dst that attacker has moved onto."""
#         past_time_thresh = move_time - datetime.timedelta(hours=self.active_cred_hrs)
#         active_cred_logins = G.es.select(_target=G.vs.find(name=new_dst).index, time_ge=past_time_thresh,
#                                          time_lt=move_time)
#
#         last_time_per_machine_user = {}
#         for edge in active_cred_logins:
#             dst_user_key = (G.vs[edge.target]['name'], edge['user'])
#             if dst_user_key not in last_time_per_machine_user:
#                 last_time_per_machine_user[dst_user_key] = max(edge['time'])
#             else:
#                 last_time_per_machine_user[dst_user_key] = max(last_time_per_machine_user[dst_user_key],
#                                                                max(edge['time']))
#
#         self.last_active_machine_user.update(last_time_per_machine_user)
#         self.log("Attack Stealthiness (update): {} active creds on {} "
#                  "(users w/ logins INTO dst within <= {} hrs)".format(
#             len(last_time_per_machine_user), new_dst, self.active_cred_hrs
#         ))
#
#     def _constraint_to_active_user_on_src(self, G, next_hops, attack_history):
#         """Constrain next hops to those that use an active cred set on src machine.
#
#         User is active on src machine if either
#         (1) user = current user conducting movement,
#         (2) new user, but that user recently logged *into* the src
#         (within/after) move time - active cred thresh
#
#         Args:
#             G: igraph.Graph object
#             next_hops: list of [AttackNextHop namedtuple's]
#             attack_history: data_types.AttackHistory object
#         """
#         min_active_time = \
#             attack_history.last_move_time - timedelta(hours=self.active_cred_hrs)
#         next_hops = [
#             hop for hop in next_hops if (
#                     hop.userId == attack_history.get_current_user() or
#                     (self.last_active_machine_user.get((hop.appId, hop.userId)) is not None and
#                      self.last_active_machine_user.get((hop.appId, hop.userId)) >= min_active_time
#                      )
#             )
#         ]
#         self.log("Attack Stealthiness: {} next hops that either continue "
#                  "current user creds OR switch to creds that recently (<= {} hrs) logged into src".format(
#             len(next_hops), self.active_cred_hrs
#         ))
#         return next_hops
#


from data_types import *
from utils import *
from datetime import timedelta


class MovementConstraints(LoggingClass):
    """Define constraints + pruning over movement paths."""
    SRC_PREF_NONE = "src_pref=none"
    SRC_PREF_FOOTHOLD = "src_pref=foothold"
    SRC_PREF_SERVER = "src_pref=server"
    SRC_PREF_CRED_SWITCH_AT_SERVER = "src_pref=cred-switch-at-server"

    MANAGEMENT_MACHINE = '-'  # machines to ignore during attack generation

    def __init__(self, src_preference=None, verbose=True):
        super(MovementConstraints, self).__init__(verbose=verbose)
        self.src_preference = src_preference
        if self.src_preference is None:
            self.src_preference = self.SRC_PREF_NONE

    def constrain_next_hops(self, G, next_hops, attack_history):
        next_hops = self._remove_invalid_user_dst_hops(G, next_hops, attack_history)
        next_hops = self._handle_jump_host_src(next_hops, attack_history)
        next_hops = self._apply_src_preference(next_hops, attack_history)
        return next_hops

    def _remove_invalid_user_dst_hops(self, G, next_hops, attack_history):
        start_user = attack_history.get_start_user()
        accessible_dst_from_start = attack_history.get_start_accessible_dst()
        next_hops = [
            hop for hop in next_hops if not (
                    hop.userId != start_user and hop.resourceId in accessible_dst_from_start
            )
        ]

        next_hops = [
            hop for hop in next_hops if not (
                    is_server_jump_host(hop.resourceId) and hop.userId != start_user
            )
        ]

        self.log("Path Constraints: {} hops after removing invalid user-dst's".format(len(next_hops)))
        return next_hops

    def _handle_jump_host_src(self, next_hops, attack_history):
        cur_machine = attack_history.get_current_machine()
        self.log("Path Constraints: currently on host = {}. Pruning any potential bastion paths accordingly.".format(
            cur_machine))
        if is_server_jump_host(cur_machine):
            next_hops = [
                hop for hop in next_hops if (
                        hop.appId == cur_machine and
                        hop.userId == attack_history.get_current_user()
                )
            ]
            self.log(
                "Path Constraints: currently on a jump host = {}, so restricting to {} hops from bastion w/ continuity.".format(
                    cur_machine, len(next_hops)))
        else:
            next_hops = [
                hop for hop in next_hops if not is_server_jump_host(hop.appId)
            ]
            self.log(
                "Path Constraints: {} hops after removing any that start from a bastion (since NOT on bastion).".format(
                    len(next_hops)))
        return next_hops

    def _apply_src_preference(self, next_hops, attack_history):
        foothold = attack_history.get_start_src()
        cur_machine = attack_history.get_current_machine()
        cur_user = attack_history.get_current_user()

        if self.src_preference == self.SRC_PREF_FOOTHOLD:
            next_hops = [hop for hop in next_hops if hop.appId == foothold]
            return next_hops

        if self.src_preference == self.SRC_PREF_SERVER:
            next_hops = [
                hop for hop in next_hops if (
                        hop.userId == cur_user or hop.appId != foothold
                )]
        elif self.src_preference == self.SRC_PREF_CRED_SWITCH_AT_SERVER:
            next_hops = [
                hop for hop in next_hops if (
                        hop.userId == cur_user or
                        (hop.userId != cur_user and hop.appId != foothold)
                )]

        next_hops = [
            hop for hop in next_hops if (
                    hop.userId == cur_user or
                    hop.userId in attack_history.compromised_creds_per_dst.get(hop.appId, [])
            )
        ]

        return next_hops


class MovementStealth(MovementConstraints):
    """Define movement's stealthiness and next hop pruning."""
    # related to particular detector: time window to confuse our path inference engine
    ACTIVE_CRED_HRS = 24
    # the length of prior history where an attacker can see what logins have
    # prev been made from a src machine (for stealthy edge movement)
    DEFAULT_SRC_HISTORY_HRS = 24 * 31

    STEALTH_NONE = ScenarioConstants.STEALTH_NONE
    STEALTH_ENDPOINTS = ScenarioConstants.STEALTH_ENDPOINTS
    STEALTH_ACTIVE_CREDS = ScenarioConstants.STEALTH_ACTIVE_CREDS
    STEALTH_FULL = ScenarioConstants.STEALTH_FULL

    def __init__(self, stealth, active_cred_hrs=None, src_history_hrs=None, src_pref=MovementConstraints.SRC_PREF_NONE,
                 verbose=True):
        super(MovementStealth, self).__init__(src_preference=src_pref, verbose=verbose)
        self.stealth = stealth

        self.last_time_src_dst = dict()
        self.last_time_src_dst_user = dict()
        self.src_history_hrs = src_history_hrs
        if not self.src_history_hrs:
            self.src_history_hrs = self.DEFAULT_SRC_HISTORY_HRS

        self.last_active_machine_user = dict()
        self.active_cred_hrs = active_cred_hrs
        if not self.active_cred_hrs:
            self.active_cred_hrs = self.ACTIVE_CRED_HRS

        self.log("Movement Stealthiness: {}\tactive cred window={} hrs\tsrc preference = {}\n".format(self.stealth,
                                                                                                      self.active_cred_hrs,
                                                                                                      src_pref))

    def constrain_next_hops(self, G, next_hops, attack_history):
        print("Attack Stealthiness: {} candidate hops prior to constraints".format(len(next_hops)))
        next_hops = self._remove_visited_dst(next_hops, attack_history)

        if self.stealth in [self.STEALTH_ACTIVE_CREDS, self.STEALTH_FULL]:
            next_hops = self._constraint_to_active_user_on_src(G, next_hops, attack_history)

        if self.stealth in [self.STEALTH_ENDPOINTS, self.STEALTH_FULL]:
            next_hops = self._constraint_to_prev_src_dst(next_hops, attack_history)

        return next_hops

    def update_knowledge(self, G, new_time, new_dst):
        """Update stealthiness state / environment knowledge.

        Args:
            G: igraph.Graph object
            new_time: datetime.datetime object
            new_dst: str (hostname)
        """
        print("TTTTTTTTTTTTTTTTT",new_time,new_dst)
        self._update_active_compromised_creds(G, new_time, new_dst)
        self._update_src_dst_recent_history(G, new_time, new_dst)

    def _remove_visited_dst(self, next_hops, attack_history):
        print(next_hops)
        next_hops = [
            hop for hop in next_hops if hop.resourceId not in attack_history.get_visited_dst()
        ]
        self.log("Attack Stealthiness: {} candidate hops after removing visited dst".format(len(next_hops)))
        return next_hops

    def _update_src_dst_recent_history(self, G, move_time, new_dst):
        """HELPER Method: Get history of where this new dst machine has launched logins into."""
        min_time = move_time - timedelta(hours=self.src_history_hrs)

        recent_logins = []
        source_index = G.vs.find(name=new_dst).index
        for edge in G.es.select(_source=source_index):
            # Filter based on time comparisons
            if any(min_time <= t <= move_time for t in edge['time']):
                recent_logins.append(edge)

        last_time_per_src_dst = {}
        for edge in recent_logins:
            src_dst_key = (G.vs[edge.source]['name'], G.vs[edge.target]['name'])
            max_time = max(t for t in edge['time'] if min_time <= t <= move_time)
            if src_dst_key not in last_time_per_src_dst:
                last_time_per_src_dst[src_dst_key] = max_time
            else:
                last_time_per_src_dst[src_dst_key] = max(
                    last_time_per_src_dst[src_dst_key], max_time)

        self.last_time_src_dst.update(last_time_per_src_dst)
        self.log("Attack Stealthiness (update): new_dst = {} has recently launched "
                 "logins into {} subsequent dst machines".format(
            new_dst, len(last_time_per_src_dst)
        ))

        last_time_per_src_dst_user = {}
        for edge in recent_logins:
            src_dst_user_key = (G.vs[edge.source]['name'], G.vs[edge.target]['name'], edge['user'])
            max_time = max(t for t in edge['time'] if min_time <= t <= move_time)
            if src_dst_user_key not in last_time_per_src_dst_user:
                last_time_per_src_dst_user[src_dst_user_key] = max_time
            else:
                last_time_per_src_dst_user[src_dst_user_key] = max(
                    last_time_per_src_dst_user[src_dst_user_key], max_time)

        self.last_time_src_dst_user.update(last_time_per_src_dst_user)

        # Debugging: print out the dictionaries
        print(f"Updated last_time_src_dst: {self.last_time_src_dst}")
        print(f"Updated last_time_src_dst_user: {self.last_time_src_dst_user}")

    def _constraint_to_prev_src_dst(self, next_hops, attack_history):
        min_active_time = attack_history.last_move_time - timedelta(hours=self.src_history_hrs)
        next_hops = [
            hop for hop in next_hops if (
                    self.last_time_src_dst.get((hop.appId, hop.resourceId)) is not None and
                    self.last_time_src_dst.get((hop.appId, hop.resourceId)) >= min_active_time
            )
        ]
        self.log(
            "Attack Stealthiness: {} next hops that traverse a prev successful src - dst edge (past {} hrs).".format(
                len(next_hops), self.src_history_hrs))

        max_stealth_next_hops = [
            hop for hop in next_hops if (
                    self.last_time_src_dst_user.get((hop.appId, hop.resourceId, hop.userId)) is not None and
                    self.last_time_src_dst_user.get((hop.appId, hop.resourceId, hop.userId)) >= min_active_time
            )
        ]
        if len(max_stealth_next_hops) > 0:
            next_hops = max_stealth_next_hops
            self.log(
                "Attack Stealthiness: {} next hops that traverse a prev successful FULL <src, dst, user> edge (past {} hrs).".format(
                    len(next_hops), self.src_history_hrs))

        # Debugging: print the constrained hops
        print(f"Constrained next_hops: {next_hops}")

        return next_hops

    def _update_active_compromised_creds(self, G, move_time, new_dst):
        """HELPER Method: What credentials are active on a dst that attacker has moved onto."""
        print("sssssssssssssssssss",move_time)
        past_time_thresh = move_time - timedelta(hours=self.active_cred_hrs)

        active_cred_logins = []
        target_index = G.vs.find(name=new_dst).index
        for edge in G.es.select(_target=target_index):
            # Filter based on time comparisons
            if any(past_time_thresh <= t <= move_time for t in edge['time']):
                active_cred_logins.append(edge)

        last_time_per_machine_user = {}
        for edge in active_cred_logins:
            dst_user_key = (G.vs[edge.target]['name'], edge['user'])
            max_time = max(t for t in edge['time'] if past_time_thresh <= t <= move_time)
            if dst_user_key not in last_time_per_machine_user:
                last_time_per_machine_user[dst_user_key] = max_time
            else:
                last_time_per_machine_user[dst_user_key] = max(
                    last_time_per_machine_user[dst_user_key], max_time)

        self.last_active_machine_user.update(last_time_per_machine_user)
        self.log("Attack Stealthiness (update): {} active creds on {} "
                 "(users w/ logins INTO dst within <= {} hrs)".format(
            len(last_time_per_machine_user), new_dst, self.active_cred_hrs
        ))

    def _constraint_to_active_user_on_src(self, G, next_hops, attack_history):
        """Constrain next hops to those that use an active cred set on src machine.

        User is active on src machine if either
        (1) user = current user conducting movement,
        (2) new user, but that user recently logged *into* the src
        (within/after) move time - active cred thresh

        Args:
            G: igraph.Graph object
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        min_active_time = attack_history.last_move_time - timedelta(hours=self.active_cred_hrs)
        next_hops = [
            hop for hop in next_hops if (
                    hop.userId == attack_history.get_current_user() or
                    (self.last_active_machine_user.get((hop.appId, hop.userId)) is not None and
                     self.last_active_machine_user.get((hop.appId, hop.userId)) >= min_active_time
                     )
            )
        ]
        self.log("Attack Stealthiness: {} next hops that either continue "
                 "current user creds OR switch to creds that recently (<= {} hrs) logged into src".format(
            len(next_hops), self.active_cred_hrs
        ))
        return next_hops


if __name__ == '__main__':
    from igraph import Graph
    from data_types import *
    from attack_start import AttackStart
    from utils import *


    # Initialize the start state with an AttackStart object
    start_state = AttackStart(start_src='app_A023', start_user='U004', start_time=datetime.now())

    # Use the AttackStart object to initialize the AttackHistory
    attack_history = AttackHistory(start_state=start_state,login_graph=G)

    next_hops = [AttackNextHop(appId='app_A023', resourceId='resource_R010', userId='U004'),
                 AttackNextHop(appId='app_A023', resourceId='resource_R002', userId='U004'),
                 AttackNextHop(appId='app_A023', resourceId='resource_R002', userId='U005')]


    stealth = MovementStealth(
        stealth=ScenarioConstants.STEALTH_FULL,
        active_cred_hrs=24,
        src_history_hrs=24 * 31,
        src_pref=MovementConstraints.SRC_PREF_NONE,
        verbose=True
    )

    constrained_hops = stealth.constrain_next_hops(G, next_hops, attack_history)
    print(constrained_hops)

    # Debugging: Print additional information
    print("\nFinal Constrained Hops:")
    for hop in constrained_hops:
        print(f"src: {hop.appId}, dst: {hop.resourceId}, user: {hop.userId}")

    # Check the state of the AttackHistory
    print("\nAttack History State:")
    print(f"Current Machine: {attack_history.get_current_machine()}")
    print(f"Current User: {attack_history.get_current_user()}")
    print(f"Visited Destinations: {attack_history.get_visited_dst()}")
    print(f"Compromised Credentials per Destination: {attack_history.compromised_creds_per_dst}")
    print(f"Number of Hops: {attack_history.num_hops}")
