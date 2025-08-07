# from login_synthesis import *
# from attack_goal import *
# from attack_stealth import *
# from login_synthesis import LoginSynthesizer
# from attack_start import *
# from data_types import *
#
# #########################################
# # Constants
# #########################################
#
# SCENARIO_GOALS = [
#     ScenarioConstants.GOAL_EXPLORATION,
#     ScenarioConstants.GOAL_SPREAD,
#     ScenarioConstants.GOAL_TARGETED
# ]
#
# SCENARIO_STEALTHS = [
#     ScenarioConstants.STEALTH_NONE, ScenarioConstants.STEALTH_ENDPOINTS,
#     ScenarioConstants.STEALTH_ACTIVE_CREDS, ScenarioConstants.STEALTH_FULL
# ]
#
# NON_COMPROMISE_HOSTS = set([])
# UNINTERESTING_DST = set([])
#
# #########################################
# # End-to-end Wrapper Method for running
# #########################################
#
# def synthesize_attack(logins, attack_config, G, start_dt=None):
#     """Method to synthesize attack from scratch.
#
#     Args:
#         logins: pd.DataFrame : one login per row
#         attack_config: attack_lib.AttackPathConfig object
#         G: igraph.Graph : graph representing the network
#         start_dt: datetime.datetime of earliest login to use
#     Return:
#         pd.DataFrame of synthesized attack logins
#     """
#     # Ensure logins have proper columns / fields
#     columns = logins.columns
#     assert(
#         LoginColumns.TIME in columns and
#         LoginColumns.SRC in columns and
#         LoginColumns.USER in columns and
#         LoginColumns.DST in columns
#         and LoginColumns.DATASET in columns
#     )
#
#     # # Restrict data set according to login type
#     # if attack_config.protocol == 'ssh':
#     #     data = logins[
#     #         logins[LoginColumns.DATASET].str.lower().str.contains('ssh')]
#     # elif attack_config.protocol == 'windows':
#     #     data = logins[
#     #         logins[LoginColumns.DATASET].str.lower().str.contains('windows')]
#     # else:
#     #     data = logins
#     # print("Using {} {} logins for attack synthesis\n".format(
#     #     len(data), attack_config.protocol))
#
#     # Generate the attack
#     attack_generator = AttackPathGenerator(
#         attack_config.attack_goal,
#         start_state=attack_config.start_state,
#         attacker_knowledge=attack_config.attacker_knowledge,
#         stealth=attack_config.attack_stealth,
#         src_preference=attack_config.src_preference,
#         src_history_hrs=attack_config.src_history_hrs,
#         compromise_cred_hrs=attack_config.compromise_cred_hrs,
#         active_cred_hrs=attack_config.active_cred_hrs,
#         target_machines=attack_config.target_machines,
#         start_dt=start_dt
#     )
#
#     attack = attack_generator.make_attack(logins, G)
#
#     return attack
#
#
# def is_synthetic_attack_successful(attack_df):
#     """Attack is unsuccessful if it fails to switch to new user credentials."""
#     if attack_df is None or len(attack_df) == 0:
#         return False
#     users = attack_df[LoginColumns.USER].drop_duplicates()
#     return len(users) >= 2
#
# #########################################
#
# class AttackPathGenerator(LoggingClass):
#     """Generate different types of lateral movement paths."""
#     VERSION = 0
#
#     def __init__(
#         self, attack_goal, attacker_knowledge, stealth,
#         start_state=None, compromise_cred_hrs=None,
#         active_cred_hrs=None, src_history_hrs=None, src_preference=None,
#         target_machines=set([]), verbose=True, start_dt=None
#     ):
#         """Initialize attack path generator.
#
#         Args:
#             attack_goal: goal constant from MovementGoal
#             attacker_knowledge: knowledge constant from AttackerCapabilities
#             stealth: constant from MovementStealth
#             state_state: utils.AttackStart object
#             compromise_cred_hrs: (int) # of hours where credentials can
#                 still be compromised after last user login
#             active_cred_hrs: (int) # of hours that a detector uses to causally
#                 link two logins setting for stealthy attacks
#             src_history_hrs: (int) # of hours for a machine's recent logins,
#                 that an attacker can mine to see stealthy prev-traversed edges
#                 they can make from a machine
#             src_preference: SRC_PREF constant from MovementConstraints
#             target_machines: set of high-value hostnames (strs)
#                 for targeted attacks
#         """
#         super(AttackPathGenerator, self).__init__(verbose=verbose)
#         self.real_users = get_all_users()
#
#         # randomly sample interarrival (seconds)
#         # between [0, self.interarrival_window_hrs] for next attack hop
#         self.interarrival_window_hrs = 2
#
#         self.start_dt = start_dt
#         self.attack_start = start_state
#         self.attack_history = None
#         self.attack_capabilities = AttackerCapabilities(
#             attacker_knowledge, compromise_cred_hrs)
#         self.attack_constraints = MovementConstraints(src_preference)
#         self.attack_stealth = MovementStealth(
#             stealth, active_cred_hrs=active_cred_hrs,
#             src_history_hrs=src_history_hrs)
#         self.attack_goal = MovementGoal(
#             attack_goal, target_machines=target_machines)
#
#     def make_attack(self, logins, G):
#         """MAIN method to generate the attack login dataframe."""
#         logins = self._preprocess_logins(logins)
#
#         # Initialize starting hop
#         self._initialize_start(logins, G)
#
#         # Iteratively generate next hop until attack goal met, or attack
#         # runs out of options
#         while not self.attack_goal.is_attack_complete(self.attack_history):
#             next_time, next_src, next_dst, next_user = self._get_next_hop(logins, G)
#
#             if next_dst is None:
#                 # Terminate if there are no more machines to move to
#                 self.log("\nWARNING: Attack ran out of potential dst. Terminating!!!\n")
#                 break
#             else:
#                 # Print progress info
#                 self.log("Selected next hop: "
#                          "(next hop time = {}, src = {}, dst = {}, user = {}.".format(
#                     next_time, next_src, next_dst, next_user
#                 ))
#
#             # Synthesize a new login event given a
#             # (1) starting machine, (2) user, (3) destination
#             new_hop = LoginSynthesizer().synthesize_login(
#                 logins, next_time, next_src, next_dst, next_user)
#             new_hop.loc[:, LoginColumns.ATTACK] = True
#
#             # Make the lateral move to the new destination & update state
#             self._make_next_hop(new_hop, logins, G)
#
#         return self.attack_history.attack_path.reset_index(drop=True)
#
#     def _preprocess_logins(self, logins):
#         """HELPER Method: Preprocess logins for attack generation."""
#         logins = logins[
#             (logins[LoginColumns.TIME] >= self.start_dt)
#         ]
#         logins = logins[logins[LoginColumns.USER].isin(self.real_users)]
#         return logins
#
#     def _engineer_attack_start(self, logins):
#         """Engineer the attack start based on stealthiness to ensure success."""
#         print("Engineering attack starting.\n")
#
#         i = 0
#         while self.attack_start is None and i < 100:
#             i += 1
#             try:
#                 if self.attack_stealth.stealth == MovementStealth.STEALTH_ACTIVE_CREDS:
#                     self.attack_start = AttackStart(AttackStart.START_AMBIG_PATH)
#                 elif self.attack_stealth.stealth == MovementStealth.STEALTH_ENDPOINTS:
#                     self.attack_start = AttackStart(AttackStart.START_LONG_PATH)
#                 elif self.attack_stealth.stealth == MovementStealth.STEALTH_FULL:
#                     self.attack_start = AttackStart(AttackStart.START_STEALTH_PATH)
#                 else:
#                     self.attack_start = AttackStart()
#                 self.attack_start.initialize(logins)
#             except:
#                 self.attack_start = None
#                 print("Failed attack start generation: {}".format(i))
#
#
#     def _initialize_start(self, logins, G):
#         """HELPER Method: Select initial compromise start + time."""
#         if self.attack_start is None:
#             i = 0
#             print("Randomized attack start.\n")
#             self.attack_start = AttackStart()
#             self.attack_start.initialize(logins)
#         else:
#             print("Pre-specified starting state given: {}\t{}\t{}".format(
#                 self.attack_start.start_time, self.attack_start.start_src,
#                 self.attack_start.start_user
#             ))
#
#         self.attack_start.initialize(logins)
#
#         self.attack_goal.target_info.initialize(
#             G, self.attack_start.start_src, self.attack_start.start_time)
#
#         self.attack_history = AttackHistory(self.attack_start)
#
#         compromised_users = set([self.attack_start.start_user,])
#         foothold = self.attack_start.start_src
#         self.attack_capabilities.initialize_capabilities(self.attack_start, G)
#         self.attack_stealth.update_knowledge(
#             self.attack_start.start_time, foothold, logins)
#         self.attack_history.update_compromised_creds(foothold, compromised_users)
#         self.attack_goal.update_progress(foothold, compromised_users)
#
#     def _make_next_hop(self, new_hop, logins, G):
#         """HELPER Method: Update state based on attack moving along next hop."""
#         self.log("Moving with new attack edge:")
#         self.log(list(new_hop[LOGIN_ANALYSIS_COLUMNS].itertuples(index=False))[0])
#
#         new_time = new_hop[LoginColumns.TIME].iloc[0]
#         new_dst = new_hop[LoginColumns.DST].iloc[0]
#
#         compromised_users = self.attack_capabilities.update_capabilities(
#             new_time, new_dst, G)
#         self.attack_stealth.update_knowledge(new_time, new_dst, logins)
#         self.attack_history.add_new_hop(new_hop)
#         self.attack_history.update_compromised_creds(new_dst, compromised_users)
#         self.attack_goal.update_progress(new_dst, compromised_users)
#
#     def _get_next_hop(self, logins, G):
#         """HELPER Method: Select the next attack hop to make."""
#         self.log("Generating attack hop #{}".format(self.attack_history.num_hops))
#
#         next_interarrival = random.randint(1, 3600 * self.interarrival_window_hrs)
#         next_time = (
#             self.attack_history.last_move_time +
#             timedelta(seconds=next_interarrival)
#         )
#
#         candidate_next_hops = self.attack_capabilities.get_candidate_next_hops(
#             self.attack_history)
#
#         candidate_next_hops = self.attack_stealth.constrain_next_hops(
#             candidate_next_hops, self.attack_history)
#
#         candidate_next_hops = self.attack_constraints.constrain_next_hops(
#             candidate_next_hops, self.attack_history)
#
#         next_hop = self.attack_goal.select_next_hop(
#             candidate_next_hops, self.attack_history, self.attack_capabilities)
#
#         return (next_time, next_hop.src, next_hop.dst, next_hop.user)
#
#
# #########################################
# # Attack Configuration Details
# #########################################
#
# class AttackPathConfig(LoggingClass):
#     """Encapsulate an attack path configuration."""
#     def __init__(
#         self, attack_goal, attacker_knowledge, stealth, protocol,
#         start_state=None,
#         src_preference=MovementConstraints.SRC_PREF_NONE,
#         compromise_cred_hrs=AttackerCapabilities.DEFAULT_CRED_EXPOSED_HRS,
#         active_cred_hrs=MovementStealth.ACTIVE_CRED_HRS,
#         src_history_hrs=MovementStealth.DEFAULT_SRC_HISTORY_HRS,
#         target_machines=set([])
#     ):
#         """Initialize attack path generator."""
#         self.attack_goal = attack_goal
#         self.attacker_knowledge = attacker_knowledge
#         self.attack_stealth = stealth
#         self.protocol = protocol
#
#         self.start_state = start_state
#         self.src_preference = src_preference
#         self.compromise_cred_hrs = compromise_cred_hrs
#         self.active_cred_hrs = active_cred_hrs
#         self.src_history_hrs = src_history_hrs
#         self.target_machines = target_machines
#
#     def get_file_suffix(self):
#         """Get suffix that describes this attack's configuration."""
#         suffix = ".{}.{}.{}.protocol={}.df"
#         suffix = suffix.format(
#             self.attack_goal, self.attack_stealth,
#             self.attacker_knowledge, self.protocol
#         )
#         return suffix
#
#     def __str__(self):
#         """Return string representation of attack config."""
#         if self.start_state:
#             start_str = "AttackStart: time = {}, src = {}, user = {}, engineering = {}.".format(
#                 self.start_state.start_time, self.start_state.start_src,
#                 self.start_state.start_user, self.start_state.start_strategy
#             )
#         else:
#             start_str = "AttackStart: None specified."
#
#         main_str = ("AttackGoal: {}.\tAttackerKnowledge: {}.\tAttackStealth: {}."
#                     "\tLoginProtocol: {}\tSourcePref: {}.\tTarget machines: {}".format(
#             self.attack_goal, self.attacker_knowledge, self.attack_stealth,
#             self.protocol, self.src_preference, self.target_machines
#         ))
#
#         auxil_str = (
#             "Cred compromise exposure window: {} hrs."
#             "\tActive cred window: {} hrs."
#             "\tSrc-Dst history window: {} hrs."
#         ).format(self.compromise_creds_hrs, self.active_cred_hrs, self.src_history_hrs)
#
#         final_str = "{}\n{}\n{}".format(start_str, main_str, auxil_str)
#         return final_str
#
# if __name__ == '__main__':
#     # Define an attack configuration
#     attack_config = AttackPathConfig(
#         attack_goal=ScenarioConstants.GOAL_EXPLORATION,
#         stealth=MovementStealth.STEALTH_NONE,
#         protocol='ssh',
#         start_state=AttackStart(start_strategy=AttackStart.START_RANDOM),attacker_knowledge='global')
#
#     # Run the synthesis
#     attack_df = synthesize_attack(df_signin, attack_config, G, start_dt=datetime(2022, 1, 1))
#
#     # Print the result
#     print(attack_df)

from login_synthesis import *
from attack_goal import *
from attack_stealth import *
from login_synthesis import LoginSynthesizer
from attack_start import *
from data_types import *
from utils import *

#########################################
# Constants
#########################################

SCENARIO_GOALS = [
    ScenarioConstants.GOAL_EXPLORATION,
    ScenarioConstants.GOAL_SPREAD,
    ScenarioConstants.GOAL_TARGETED
]

SCENARIO_STEALTHS = [
    ScenarioConstants.STEALTH_NONE, ScenarioConstants.STEALTH_ENDPOINTS,
    ScenarioConstants.STEALTH_ACTIVE_CREDS, ScenarioConstants.STEALTH_FULL
]

NON_COMPROMISE_HOSTS = set([])
UNINTERESTING_DST = set([])

#########################################
# End-to-end Wrapper Method for running
#########################################

def synthesize_attack(logins, attack_config, graph, start_dt=None):
    """Method to synthesize attack from scratch using graph.

    Args:
        logins: pd.DataFrame : one login per row (used by LoginSynthesizer)
        attack_config: attack_lib.AttackPathConfig object
        G: igraph.Graph : graph representing the network
        start_dt: datetime.datetime of earliest login to use
    Return:
        pd.DataFrame of synthesized attack logins
    """
    # Ensure logins have proper columns / fields
    columns = logins.columns
    assert(
        LoginColumns.TIME in columns and
        LoginColumns.SRC in columns and
        LoginColumns.USER in columns and
        LoginColumns.DST in columns
        and LoginColumns.DATASET in columns
    )

    # Generate the attack using the graph `G` for path decisions
    attack_generator = AttackPathGenerator(
        attack_config.attack_goal,
        start_state=attack_config.start_state,
        attacker_knowledge=attack_config.attacker_knowledge,
        stealth=attack_config.attack_stealth,
        src_preference=attack_config.src_preference,
        src_history_hrs=attack_config.src_history_hrs,
        compromise_cred_hrs=attack_config.compromise_cred_hrs,
        active_cred_hrs=attack_config.active_cred_hrs,
        target_machines=attack_config.target_machines,
        start_dt=start_dt
    )

    # Run the attack generation process
    attack = attack_generator.make_attack(logins, graph)

    return attack



def is_synthetic_attack_successful(attack_df):
    """Attack is unsuccessful if it fails to switch to new user credentials."""
    if attack_df is None or len(attack_df) == 0:
        return False
    users = attack_df[LoginColumns.USER].drop_duplicates()
    return len(users) >= 2

#########################################

class AttackPathGenerator(LoggingClass):
    """Generate different types of lateral movement paths."""
    VERSION = 0

    def __init__(
        self, attack_goal, attacker_knowledge, stealth,
        start_state=None, compromise_cred_hrs=None,
        active_cred_hrs=None, src_history_hrs=None, src_preference=None,
        target_machines=set([]), verbose=True, start_dt=None
    ):
        super(AttackPathGenerator, self).__init__(verbose=verbose)
        self.real_users = get_all_users()
        self.start_dt = start_dt
        self.attack_start = start_state
        self.interarrival_window_hrs = 2
        self.attack_history = None
        self.attack_capabilities = AttackerCapabilities(
            attacker_knowledge, compromise_cred_hrs)
        self.attack_constraints = MovementConstraints(src_preference)
        self.attack_stealth = MovementStealth(
            stealth, active_cred_hrs=active_cred_hrs,
            src_history_hrs=src_history_hrs)
        self.attack_goal = MovementGoal(
            attack_goal, target_machines=target_machines)

    def make_attack(self, logins, G):
        """MAIN method to generate the attack using the graph."""
        logins = self._preprocess_logins(logins)

        # Initialize starting hop
        self._initialize_start(logins, G)

        # Iteratively generate next hop until attack goal met, or attack
        # runs out of options
        while not self.attack_goal.is_attack_complete(self.attack_history):
            next_time, next_src, next_dst, next_user = self._get_next_hop(G)

            if next_dst is None:
                self.log("\nWARNING: Attack ran out of potential dst. Terminating!!!\n")
                break
            else:
                self.log(f"Selected next hop: next hop time = {next_time}, src = {next_src}, dst = {next_dst}, user = {next_user}.")
            print(next_src, next_dst, next_user)

            # Synthesize a new login event (uses DataFrame)
            new_hop = LoginSynthesizer().synthesize_login(
                logins, next_time, next_src, next_dst, next_user)
            new_hop.loc[:, LoginColumns.ATTACK] = True

            # Make the lateral move to the new destination & update state (using graph)
            self._make_next_hop(new_hop, logins, G)

        return self.attack_history.attack_path.reset_index(drop=True)

    def _preprocess_logins(self, logins):
        """Prepare logins by filtering based on start date and known users."""
        if logins[LoginColumns.TIME].dtype == 'object':
            logins[LoginColumns.TIME] = pd.to_datetime(logins[LoginColumns.TIME], utc=True)
        logins = logins[logins[LoginColumns.TIME] >= self.start_dt]
        logins = logins[logins[LoginColumns.USER].isin(self.real_users)]
        return logins

    def _initialize_start(self, logins, G):
        """Select initial compromise start + time."""
        print("Starting _initialize_start...")

        # Initialize attack start, regardless of whether it's pre-specified or not
        if self.attack_start is None:
            print("No pre-specified attack start. Randomizing...")
            self.attack_start = AttackStart()
        else:
            print("Pre-specified starting state provided.")

        # Ensure the attack start is initialized using the graph
        self.attack_start.initialize(G)

        # Debugging output to ensure initialization is correct
        print(
            f"Initial time, src, user selected: (time = {self.attack_start.start_time}, src = {self.attack_start.start_src}, user = {self.attack_start.start_user})")

        # Initialize the target info with the start source and time
        self.attack_goal.target_info.initialize(G, self.attack_start.start_src, self.attack_start.start_time)
        print("Target info initialized.")

        # Create attack history using the initialized attack start
        self.attack_history = AttackHistory(self.attack_start, G)
        print(f"Attack history initialized with starting state: {self.attack_history}")

        # Determine the compromised users based on the start state
        compromised_users = set([self.attack_start.start_user])
        foothold = self.attack_start.start_src
        print(f"Foothold: {foothold}, Compromised users: {compromised_users}")

        # Initialize attacker capabilities
        self.attack_capabilities.initialize_capabilities(self.attack_start, G)
        print("Attacker capabilities initialized.")

        # Update the attack stealth knowledge based on the initial foothold
        self.attack_stealth.update_knowledge(G, self.attack_start.start_time, foothold)
        print(f"Attack stealth updated with foothold: {foothold}")

        # Update the attack history with the compromised credentials
        self.attack_history.update_compromised_creds(foothold, compromised_users)
        print("Attack history updated with compromised credentials.")

        # Update the attack progress within the movement goal
        self.attack_goal.update_progress(foothold, compromised_users)
        print("Attack progress updated within movement goal.")

        # Final debugging output to confirm setup
        print(f"Setup complete with foothold: {foothold} and compromised users: {compromised_users}")
        print("Exiting _initialize_start.")

    def _make_next_hop(self, new_hop, logins, G):
        """Update state based on attack moving along next hop."""
        self.log(f"Moving with new attack edge: {list(new_hop[LOGIN_ANALYSIS_COLUMNS].itertuples(index=False))[0]}")
        new_time = new_hop[LoginColumns.TIME].iloc[0]
        new_dst = new_hop[LoginColumns.DST].iloc[0]

        compromised_users = self.attack_capabilities.update_capabilities(new_time, new_dst, G)
        self.attack_stealth.update_knowledge(G, new_time, new_dst)
        self.attack_history.add_new_hop(new_hop)
        self.attack_history.update_compromised_creds(new_dst, compromised_users)
        self.attack_goal.update_progress(new_dst, compromised_users)

    def _get_next_hop(self, G):
        """Select the next attack hop to make."""
        self.log(f"Generating attack hop #{self.attack_history.num_hops}")
        next_interarrival = random.randint(1, 3600 * self.interarrival_window_hrs)
        next_time = self.attack_history.last_move_time + timedelta(seconds=next_interarrival)

        candidate_next_hops = self.attack_capabilities.get_candidate_next_hops(self.attack_history, G)
        candidate_next_hops = self.attack_stealth.constrain_next_hops(G,candidate_next_hops, self.attack_history)
        candidate_next_hops = self.attack_constraints.constrain_next_hops(G,candidate_next_hops, self.attack_history)

        next_hop = self.attack_goal.select_next_hop(candidate_next_hops, self.attack_history, self.attack_capabilities)
        return (next_time, next_hop.appId, next_hop.resourceId, next_hop.userId)



#########################################
# Attack Configuration Details
#########################################

class AttackPathConfig(LoggingClass):
    """Encapsulate an attack path configuration."""
    def __init__(
        self, attack_goal, attacker_knowledge, stealth, protocol,
        start_state=None,
        src_preference=MovementConstraints.SRC_PREF_NONE,
        compromise_cred_hrs=AttackerCapabilities.DEFAULT_CRED_EXPOSED_HRS,
        active_cred_hrs=MovementStealth.ACTIVE_CRED_HRS,
        src_history_hrs=MovementStealth.DEFAULT_SRC_HISTORY_HRS,
        target_machines=set([])
    ):
        """Initialize attack path generator."""
        self.attack_goal = attack_goal
        self.attacker_knowledge = attacker_knowledge
        self.attack_stealth = stealth
        self.protocol = protocol

        self.start_state = start_state
        self.src_preference = src_preference
        self.compromise_cred_hrs = compromise_cred_hrs
        self.active_cred_hrs = active_cred_hrs
        self.src_history_hrs = src_history_hrs
        self.target_machines = target_machines

    def get_file_suffix(self):
        """Get suffix that describes this attack's configuration."""
        suffix = ".{}.{}.{}.protocol={}.df"
        suffix = suffix.format(
            self.attack_goal, self.attack_stealth,
            self.attacker_knowledge, self.protocol
        )
        return suffix

    def __str__(self):
        """Return string representation of attack config."""
        if self.start_state:
            start_str = "AttackStart: time = {}, src = {}, user = {}, engineering = {}.".format(
                self.start_state.start_time, self.start_state.start_src,
                self.start_state.start_user, self.start_state.start_strategy
            )
        else:
            start_str = "AttackStart: None specified."

        main_str = ("AttackGoal: {}.\tAttackerKnowledge: {}.\tAttackStealth: {}."
                    "\tLoginProtocol: {}\tSourcePref: {}.\tTarget machines: {}".format(
            self.attack_goal, self.attacker_knowledge, self.attack_stealth,
            self.protocol, self.src_preference, self.target_machines
        ))

        auxil_str = (
            "Cred compromise exposure window: {} hrs."
            "\tActive cred window: {} hrs."
            "\tSrc-Dst history window: {} hrs."
        ).format(self.compromise_cred_hrs, self.active_cred_hrs, self.src_history_hrs)

        final_str = "{}\n{}\n{}".format(start_str, main_str, auxil_str)
        return final_str


if __name__ == '__main__':
    import pytz
    import pandas as pd
    from attack_start import AttackStart
    # import datetime
    start = AttackStart(start_strategy=AttackStart.START_RANDOM)
    start.initialize(G)
    # Define an attack configuration
    attack_config = AttackPathConfig(
        attack_goal=ScenarioConstants.GOAL_SPREAD,
        stealth=MovementStealth.STEALTH_NONE,
        protocol='ssh',
        start_state=start, attacker_knowledge='global')
    start_dt = datetime(2022, 1, 1, tzinfo=pytz.UTC)

    # Run the synthesis
    attack_df = synthesize_attack(logins=df_signin,attack_config= attack_config,graph= G, start_dt=start_dt)

    # Print the result
    print(attack_df)
    attack_df.to_csv("att.csv")
