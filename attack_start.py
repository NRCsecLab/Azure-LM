from data_types import *
from utils import *
import random
import igraph as ig
from datetime import datetime, timedelta
from attack_capabilities import AttackerCapabilities


def get_viable_start_users(G, target_dsts=set([])):
    """HELPER Method: Viable start users = non-sysadmins."""
    direct_access_users = set()
    if target_dsts:
        for target in target_dsts:
            target_vertex = G.vs.find(name=f'resource_{target}')
            neighbors = G.neighbors(target_vertex, mode='in')
            for neighbor in neighbors:
                if G.vs[neighbor]['type'] == 'user':
                    direct_access_users.add(G.vs[neighbor]['label'])

    real_users = get_all_users()
    candidate_users = real_users  # Remove the "user_" prefix
    # sysadmins = get_sysadmin_users()  # Uncomment if sysadmin data is available
    # candidate_users = candidate_users - sysadmins

    login_users = {v['label'] for v in G.vs if v['type'] == 'user'}

    # Debugging: Print contents of both sets
    print("Login Users:", login_users)
    print("Candidate Users:", candidate_users)

    intersection = login_users.intersection(candidate_users)
    print("Intersection of Login Users and Candidate Users:", intersection)

    return intersection


class AttackStart(object):
    """Select the initial point of compromise."""
    MIN_START_DAYS = 14  # min age (days) for initially compromised user/machine
    RAND_START_OFFSET_SEC = 86400 * 5  # rand offset to choose for start time

    START_RANDOM = "start:random"
    START_GUARANTEE_RANDOM = "start:random:guaranteed-attack"
    START_AMBIG_PATH = "start:unclear-cred-switch-path"
    START_LONG_PATH = "start:long-path-guaranteed"
    START_STEALTH_PATH = "start:stealth-path"

    def __init__(self, start_strategy=None, start_user=None, start_time=None, start_src=None):
        self.min_age = self.MIN_START_DAYS
        self.start_time = start_time
        self.start_src = start_src
        self.start_user = start_user
        self.start_accessible_dst = None
        self.target_dsts = set([])

        self.start_strategy = start_strategy
        if self.start_strategy is None:
            self.start_strategy = self.START_RANDOM

        self.elevation_opportunities_per_start_user = None

    @classmethod
    def time_box_logins_for_user_src(cls, G, start_user, start_src, min_time=None):
        """Bound the logins within user's activity on src."""
        user_vertex = G.vs.find(name=f'{start_user}')
        src_vertex = G.vs.find(name=start_src)

        if not min_time:
            min_time = min(itertools.chain(*G.es.select(_source=user_vertex.index, _target=src_vertex.index)['time']))

        max_time = max(
            itertools.chain(*G.es.select(_source=user_vertex.index, _target=src_vertex.index)['time'])) + timedelta(
            days=7)

        valid_edges = G.es.select(lambda e: min_time <= min(
            e['time']) <= max_time and e.source == user_vertex.index and e.target == src_vertex.index)
        return valid_edges

    def initialize(self, G, target_dsts=set([])):
        """MAIN METHOD: Get the initial point of compromise + time."""
        self.target_dsts = target_dsts

        if not all([v is not None for v in [self.start_time, self.start_src, self.start_user]]):
            self._select_start_user(G)
            self._select_start_src(G)
            self._select_start_time(G)

        print(f"Initial time, src, user selected: (time = {self.start_time}, src = {self.start_src}, user = {self.start_user})")
        print_divider()

        self.start_accessible_dst = AttackerCapabilities.get_accessible_dst_for_user(G, self.start_user)

    def _select_start_user(self, G):
        """Select starting user."""
        if self.start_user:
            print(f"Starting user PRE-set to = {self.start_user}")
            return

        if self.start_strategy == self.START_RANDOM and not self.start_user:
            self._select_start_user_random(G)
        elif self.start_strategy in [self.START_LONG_PATH, self.START_STEALTH_PATH]:
            self._select_start_user_guaranteed_long_path(G)
        else:
            self._select_start_user_guaranteed_random(G)

    def _select_start_src(self, G):
        """Get machine for corresponding compromised start user."""
        assert (self.start_user is not None or self.start_src is not None)
        if self.start_src:
            print(f"Starting src PRE-set to = {self.start_src}")
        else:
            self.start_src = self._get_src_machine_for_user(self.start_user, G)

    def _select_start_time(self, G, min_time=None):
        """HELPER Method: Select starting attack time."""
        if self.start_time:
            print(f"Specific starting time set = {self.start_time}")
            return

        valid_edges = self.time_box_logins_for_user_src(G, self.start_user, self.start_src, min_time=min_time)

        if self.start_strategy == self.START_RANDOM:
            self._select_start_time_random(valid_edges)
        elif self.start_strategy in [self.START_AMBIG_PATH, self.START_STEALTH_PATH]:
            self._select_start_time_confusion_paths(G, valid_edges)
        else:
            self._select_start_time_guaranteed_lm(G, valid_edges)

    def _select_start_time_guaranteed_lm(self, G, valid_edges):
        """Select a start time that guarantees ability to access new creds w/ new dst."""
        # Ensure we have valid edges to choose from
        if not valid_edges:
            print("No valid edges found. Cannot set a guaranteed start time.")
            return

        # Filter valid edges by their weights to find the most significant ones
        max_weight = max(e['weight'] for e in valid_edges)
        significant_edges = [e for e in valid_edges if e['weight'] == max_weight]

        # Select a random edge from the significant edges
        selected_edge = random.choice(significant_edges)
        selected_time = random.choice(selected_edge['time'])  # Select a random time from the edge's list of times
        self.start_time = selected_time
        rand_seconds = random.randint(1, self.RAND_START_OFFSET_SEC)
        self.start_time = self.start_time + timedelta(seconds=rand_seconds)
        print(f"Selected start time: {self.start_time}")

    def _select_start_time_confusion_paths(self, G, valid_edges):
        """Select a start time ensuring maximum ambiguity in credential-switching paths."""
        if self.start_time:
            print(f"Specific starting time set = {self.start_time}")
            return

        real_users = get_all_users()
        users_per_app = {v['name']: set(G.vs[G.neighbors(v, mode='in')]['label']) for v in G.vs if v['type'] == 'app'}
        users_per_app = {app: users for app, users in users_per_app.items() if len(users) > 2}

        if not users_per_app:
            print("No applications with multiple users found.")
            return

        # Identify applications with high in-degree (indicating high access rates)
        high_access_apps = [
            v['name'] for v in G.vs if v['type'] == 'app' and G.degree(v, mode='in') > 2
        ]

        viable_intermediates = [app for app in users_per_app if
                                app in high_access_apps and self.start_user in users_per_app[app]]
        if not viable_intermediates:
            print("No viable intermediates found for ambiguity.")
            return

        # Track overlapping time windows
        overlapping_windows = []

        for app in viable_intermediates:
            accesses = []
            for user in users_per_app[app]:
                if user != self.start_user:
                    user_vertex = G.vs.find(name=f'user_{user}')
                    app_vertex = G.vs.find(name=app)
                    for e in G.es.select(_source=user_vertex.index, _target=app_vertex.index):
                        accesses.extend(e['time'])

            # Find overlapping time windows
            accesses.sort()
            for i in range(len(accesses)):
                for j in range(i + 1, len(accesses)):
                    if accesses[j] - accesses[i] < timedelta(hours=1):  # Overlapping within 1 hour
                        overlapping_windows.append((accesses[i], accesses[j]))

        if not overlapping_windows:
            print("No overlapping access windows found for ambiguity.")
            return

        # Select the most ambiguous time window (maximum overlaps)
        most_ambiguous_window = max(overlapping_windows, key=lambda window: window[1] - window[0])
        self.start_time = most_ambiguous_window[0]
        print(f"Selected ambiguous start time: {self.start_time} (from {len(overlapping_windows)} candidate windows).")
        print_small_divider()

        rand_seconds = random.randint(1, 86400 // 2)
        self.start_time = self.start_time + timedelta(seconds=rand_seconds)

    # def _select_start_time_random(self, valid_edges):
    #     """Select a random start time after a min threshold"""
    #     self.start_time = min(random.choice(valid_edges)['time'])
    #     rand_seconds = random.randint(1, self.RAND_START_OFFSET_SEC)
    #     self.start_time = self.start_time + timedelta(seconds=rand_seconds)

    def _select_start_time_random(self, valid_edges):
        """Select a random start time after a min threshold"""
        selected_edge = random.choice(valid_edges)
        selected_time = random.choice(selected_edge['time'])  # Select a random time from the edge's list of times
        self.start_time = selected_time
        rand_seconds = random.randint(1, self.RAND_START_OFFSET_SEC)
        self.start_time = self.start_time + timedelta(seconds=rand_seconds)
        print(f"Selected start time: {self.start_time}")
    def _select_start_user_guaranteed_long_path(self, G):
        """HELPER Method: Constrained start generation to guarantee attacker has long path option."""
        print("Engineering start to ensure initial victim has long path potential.")
        print_small_divider()

        min_time_per_intermediate_dsts = self._get_intermediate_dsts(G)
        vuln_intermediates = set(min_time_per_intermediate_dsts.keys())
        print(f"Start user selection: engineering to ensure that start user has access to one of {len(vuln_intermediates)} intermediate dst: {vuln_intermediates}")

        self._select_start_user_guaranteed_random(G, vuln_intermediates=vuln_intermediates)

    # def _select_start_user_guaranteed_random(self, G):
    #     """Select a start user ensuring random access opportunities."""
    #     # Get all users and their accessible applications
    #     apps_per_user = {v['label']: set(G.vs[G.neighbors(v, mode='out')]['name']) for v in G.vs if v['type'] == 'user'}
    #     users_per_app = {v['name']: set(G.vs[G.neighbors(v, mode='in')]['label']) for v in G.vs if v['type'] == 'app'}
    #
    #     # Filter users who can access multiple applications
    #     multi_access_users = {user: apps for user, apps in apps_per_user.items() if len(apps) > 1}
    #     print(f"Users with multiple access opportunities: {multi_access_users}")
    #
    #     if not multi_access_users:
    #         print("No users with multiple access opportunities found.")
    #         return
    #
    #     # Randomly select a user from those who can access multiple applications
    #     start_user = random.choice(list(multi_access_users.keys()))
    #     accessible_apps = multi_access_users[start_user]
    #
    #     print(f"Randomly selected start user: {start_user}")
    #     print(f"Accessible applications for {start_user}: {accessible_apps}")
    #
    #     # Filter accessible applications to ensure they have multiple users
    #     valid_accessible_apps = [app for app in accessible_apps if len(users_per_app[app]) > 1]
    #     if not valid_accessible_apps:
    #         print(f"No valid applications for user {start_user} found with multiple users.")
    #         return
    #
    #     # Randomly select a valid application from the accessible applications
    #     start_app = random.choice(valid_accessible_apps)
    #
    #     print(f"Randomly selected start application: {start_app}")
    #
    #     # Ensure lateral movement opportunities from the selected application
    #     other_users = users_per_app[start_app] - {start_user}
    #     if other_users:
    #         print(f"Other users accessing {start_app}: {other_users}")
    #         self.start_user = start_user
    #         self.start_src = start_app
    #         self.elevation_opportunities_per_start_user = {start_user: {(user, start_app) for user in other_users}}
    #     else:
    #         print(f"No other users accessing {start_app} for lateral movement.")
    def _select_start_user_guaranteed_random(self, G, vuln_intermediates=None):
        """Select a start user ensuring random access opportunities."""
        # Get all users and their accessible applications
        apps_per_user = {v['label']: set(G.vs[G.neighbors(v, mode='out')]['name']) for v in G.vs if v['type'] == 'user'}
        users_per_app = {v['name']: set(G.vs[G.neighbors(v, mode='in')]['label']) for v in G.vs if v['type'] == 'app'}

        if vuln_intermediates:
            # Filter users who can access vulnerable intermediate applications
            apps_per_user = {user: apps & vuln_intermediates for user, apps in apps_per_user.items() if
                             apps & vuln_intermediates}
            users_per_app = {app: users for app, users in users_per_app.items() if app in vuln_intermediates}

        # Filter users who can access multiple applications
        multi_access_users = {user: apps for user, apps in apps_per_user.items() if len(apps) > 1}
        print(f"Users with multiple access opportunities: {multi_access_users}")

        if not multi_access_users:
            print("No users with multiple access opportunities found.")
            return

        # Randomly select a user from those who can access multiple applications
        start_user = random.choice(list(multi_access_users.keys()))
        accessible_apps = multi_access_users[start_user]

        print(f"Randomly selected start user: {start_user}")
        print(f"Accessible applications for {start_user}: {accessible_apps}")

        # Filter accessible applications to ensure they have multiple users
        valid_accessible_apps = [app for app in accessible_apps if len(users_per_app[app]) > 1]
        if not valid_accessible_apps:
            print(f"No valid applications for user {start_user} found with multiple users.")
            return

        # Randomly select a valid application from the accessible applications
        start_app = random.choice(valid_accessible_apps)

        print(f"Randomly selected start application: {start_app}")

        # Ensure lateral movement opportunities from the selected application
        other_users = users_per_app[start_app] - {start_user}
        if other_users:
            print(f"Other users accessing {start_app}: {other_users}")
            self.start_user = start_user
            self.start_src = start_app
            self.elevation_opportunities_per_start_user = {start_user: {(user, start_app) for user in other_users}}
        else:
            print(f"No other users accessing {start_app} for lateral movement.")
            self._select_start_user_guaranteed_random(G, vuln_intermediates)  # Retry with a different random selection

    def _select_start_user_random(self, G, candidate_start_users=None):
        """Select starting user from random."""
        user_vertices = G.vs.select(type='user')
        if self.start_time:
            start_time_unix = self.start_time.timestamp()
            user_vertices = [v for v in user_vertices if any(
                start_time_unix - 86400 <= t <= start_time_unix + 86400 for t in G.es.select(_source=v.index)['time'])]

        if not candidate_start_users:
            candidate_start_users = self._get_viable_start_users(G)
            print(candidate_start_users)

        candidate_start_users = list(candidate_start_users)  # Convert to list for sampling
        self.start_user = random.sample(candidate_start_users, 1)[0]
        print(
            f"Starting user: Randomly selected {self.start_user} from {len(candidate_start_users)} viable start users.")

    def _get_viable_start_users(self, G):
        """HELPER Method: Viable start users = non-sysadmins."""
        return get_viable_start_users(G, self.target_dsts)

    def _get_src_machine_for_user(self, user, G):
        """Get src machine for user."""
        # user_vertex = G.vs.find(name=f'user_{user}')
        user_vertex = G.vs.find(name=f'{user}')

        client_edges = G.es.select(_source=user_vertex.index, is_src_client=True)
        client_srcs = {G.vs[e.target]['name'] for e in client_edges}

        for src in client_srcs:
            owners = {G.vs[e.target]['label'] for e in G.es.select(_source=G.vs.find(name=src).index, is_src_client=True)}
            if user in owners:
                return src

        return random.choice(list(client_srcs))

    def _get_intermediate_dsts(self, G):
        """Get destinations that also launch logins."""
        # Ensure we only consider vertices with edges
        min_time_per_dst = {
            v['name']: min(G.es.select(_target=v.index)['time'])
            for v in G.vs if v['type'] == 'app' and G.es.select(_target=v.index)
        }
        min_time_per_src = {
            v['name']: min(G.es.select(_source=v.index)['time'])
            for v in G.vs if v['type'] == 'app' and G.es.select(_source=v.index)
        }

        intermediate_dsts = [
            node for node in min_time_per_src if node in min_time_per_dst and not is_server_jump_host(node)
        ]
        min_time_per_intermediate_dsts = {
            node: max(min_time_per_dst[node], min_time_per_src[node]) for node in intermediate_dsts
        }
        print(f"{len(min_time_per_intermediate_dsts)} app nodes are INTERMEDIARIES that have launched logins as srcs.")
        return min_time_per_intermediate_dsts

    # def _filter_logins_for_start(self, G):
    #     """HELPER Method: Prune login set to suitable set for initial compromise."""
    #     avoid_dsts = UNINTERESTING_DST | NON_COMPROMISE_HOSTS
    #     real_users = get_all_users()
    #     sysadmins = get_sysadmin_users()
    #
    #     valid_logins = [e for e in G.es if G.vs[e.target]['name'] not in avoid_dsts and G.vs[e.source]['label'] in real_users and G.vs[e.source]['label'] not in sysadmins]
    #
    #     print(f"{len(valid_logins)} candidate logins for initial attack state (non-sysadmin, real-user, and not-new).")
    #
    #     min_time = datetime.utcfromtimestamp(min(e['time'] for e in G.es) + timedelta(weeks=2).total_seconds())
    #     max_time = datetime.utcfromtimestamp(max(e['time'] for e in G.es) - timedelta(weeks=1).total_seconds())
    #
    #     valid_logins = [e for e in valid_logins if min_time <= min(e['time']) <= max_time]
    #
    #     print(f"{len(valid_logins)} candidate logins ({len(set(G.vs[e.source]['label'] for e in valid_logins))} users) after narrowing timeframe to middle of batch ({min_time} - {max_time}).")
    #
    #     return valid_logins

if __name__ == '__main__':
    import datetime
    # Initialize the attack start configuration
    # attack_start = AttackStart(start_strategy=AttackStart.START_RANDOM)
    # Example of initializing AttackStart
    attack_start = AttackStart(start_strategy=AttackStart.START_RANDOM)

    # Determine the initial point of compromise
    attack_start.initialize(G)

    # Output the selected starting time, source, and user
    print(f"Initial time: {attack_start.start_time}")
    print(f"Starting source: {attack_start.start_src}")
    print(f"Starting user: {attack_start.start_user}")
