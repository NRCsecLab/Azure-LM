# import datetime
# import pandas as pd
# import numpy as np
#
# from data_types import *
# from utils import *
#
# # LOGIN_ANALYSIS_COLUMNS = [
# #     LoginColumns.TIME, LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER,EnrichmentColumns.DEVICE_ID, EnrichmentColumns.OPERATING_SYSTEM,
# #     EnrichmentColumns.BROWSER,
# #     EnrichmentColumns.NUM_INBOUND_DAYS, EnrichmentColumns.MACHINE_AGE,
# #     LoginColumns.ATTACK, LoginColumns.ATTACK_ID
# # ]
#
# LOGIN_ANALYSIS_COLUMNS = [
#     LoginColumns.TIME, LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER, EnrichmentColumns.SRC_SUBNET
# ]
#
#
# class MovementLabeler(MovementTypes):
#     """Class for labeling login movement types."""
#     def __init__(self):
#         self.col = LoginColumns.MOVEMENT_TYPE
#
#     def label_movement_into_client(self, logins):
#         """Label a login if client -> server (single hop)."""
#         client_dst = (logins[EnrichmentColumns.DEVICE_ID].str.contains('client', na=False))
#         logins.loc[client_dst, self.col] = self.MOVE_INTO_CLIENT
#         return logins
#
#     def label_movement_from_client(self, logins):
#         """Label a login that goes into client (single hop)."""
#         unassigned = logins[self.col].isnull()
#         client_mask = (logins[EnrichmentColumns.DEVICE_ID].str.contains('client', na=False))
#
#         modify_mask = (unassigned & client_mask)
#         logins.loc[modify_mask, self.col] = self.MOVE_FROM_CLIENT
#         return logins
#
#     def label_movement_from_server(self, logins):
#         """Label a login from server -> server (paths)."""
#         unassigned = logins[self.col].isnull()
#         server_mask = ~(logins[EnrichmentColumns.DEVICE_ID].str.contains('client', na=False))
#
#         modify_mask = (unassigned & server_mask)
#         logins.loc[modify_mask, self.col] = self.MOVE_FROM_SERVER
#         return logins
#
#     def label_movement(self, logins):
#         """Label dataframe of logins."""
#         if self.col not in logins.columns:
#             logins[self.col] = np.nan
#
#         logins[self.col] = logins[self.col].astype(object)  # Ensure the column type is compatible
#
#         # Set aside any logins that already have movement labels
#         movement_types = set([
#             self.MOVE_FROM_CLIENT, self.MOVE_INTO_CLIENT,
#             self.MOVE_FROM_SERVER
#         ])
#         labeled_logins_mask = logins[self.col].isin(movement_types)
#         labeled_logins = logins[labeled_logins_mask]
#
#         unlabeled_logins = logins[~labeled_logins_mask]
#         unlabeled_logins = self.label_movement_into_client(unlabeled_logins)
#         unlabeled_logins = self.label_movement_from_client(unlabeled_logins)
#         unlabeled_logins = self.label_movement_from_server(unlabeled_logins)
#
#         return pd.concat([labeled_logins, unlabeled_logins], sort=False)
#
# class LoginSynthesizer(object):
#     """Class for creating an artificial login event.
#
#     Abstraction: Given a <time, src, dst, user> of a fake login event to generate,
#     create a fully-fleshed event with as much realistic metadata / enrichment attributes
#     as possible (e.g., add the src host information, such as client vs. server, owner, etc.)
#     and return a full-schema event for the fake login.
#     """
#     DATASET_ATTACK_SUCCESS = 'attack:success'
#
#     def __init__(self, login_type=None):
#         if not login_type:
#             login_type = self.DATASET_ATTACK_SUCCESS
#
#         self.login_type = login_type
#
#     def log(self, msg):
#         """Helper Method: Log message depending on verbose or not."""
#         print(msg)
#
#     def synthesize_login(self, logins, time, src, dst, user):
#         """MAIN METHOD: Create a fake login tuple with realistic attributes.
#
#         Args:
#             logins: pd.DataFrame of real logins
#             time: datetime.datetime object: time when the fake attack will occur
#             src: (str) hostname of machine to launch the login from
#             dst: (str) hostname of machine that login accesses
#             user: (str) username / credentials to use in remote login
#         Returns:
#             pandas DataFrame (one row) that holds the fake login's information
#         """
#         # Try to find a real login that matches the <src, dst, user> we're synthesizing
#         attack_df = logins[
#             (logins[LoginColumns.SRC] == src) &
#             (logins[LoginColumns.DST] == dst) &
#             (logins[LoginColumns.USER] == user)
#             ]
#
#         if len(attack_df) > 0:
#             # If the fake login has actually has occurred,
#             # find the closest corresponding real login and copy over its information
#             attack_df = self._get_closest_login(attack_df, time)
#             self.log("Synthesizing login info:  Synthetic attack edge: "
#                      "{} exists. Reusing.".format(
#                 attack_df.head(1)[LOGIN_ANALYSIS_COLUMNS].to_dict()
#             ))
#         else:
#             # If the fake login's edge <src, dst, user> has never occurred,
#             # construct a fake login event by mashing together metadata
#             # from real logins that involved the src / dst / user separately
#             closest_src, closest_user, closest_dst = self._get_synthetic_login_templates(
#                 logins, time, src, dst, user
#             )
#             self.log("Synthesizing login info: Constructing attack edge from SCRATCH:"
#                      "\nsrc ({}) login: {}\ndst ({}) login: {}\nuser ({}) login: {}".format(
#                 src, closest_src[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#                 dst, closest_dst[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#                 user, closest_user[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#             ))
#
#             # Create a dummy event that we will overwrite with the mash-up of login events above
#             # Goal = reuse the closest src login as the dummy event to fill in
#             base_login = self._create_base_login_from_src(closest_src)
#             if base_login is None:
#                 # However, we might have selected a src that's never launched logins,
#                 # in this case, take the dst login and do some extra work to format.
#                 base_login = self._create_base_login_from_dst(closest_dst, src)
#
#             # Overwrite the dummy event's attributes with the mash-up of src/dst/user login events
#             attack_df = self._merge_into_new_login(
#                 base_login, closest_src, closest_dst, closest_user)
#
#         # Set the fake login's time to the specified time
#         attack_df.loc[:, LoginColumns.TIME] = time
#         attack_df.loc[:, LoginColumns.TIME] = pd.to_datetime(
#             attack_df[LoginColumns.TIME]).copy()
#
#         # Ensure these critical fields are set correctly
#         attack_df.loc[:, LoginColumns.SRC] = src
#         attack_df.loc[:, LoginColumns.DST] = dst
#         attack_df.loc[:, LoginColumns.USER] = user
#
#         # Update the inbound login count to this src based on global history
#         # This handles the case where the attacker moves to and launches logins from
#         # a (src) machine that receives logins, but never launches them
#         # (thus no src login will be found and the inbound days col will incorrectly be NaN)
#         attack_df.loc[:, EnrichmentColumns.NUM_INBOUND_DAYS] = len(
#             logins[logins[LoginColumns.DST] == src][LoginColumns.DAY_COL].drop_duplicates()
#         )
#
#         # Set some final fields for the fake login event to make clear it's a fake / attack event
#         attack_df = self._format_synthetic_login(attack_df)
#
#         return attack_df
#
#     def _get_closest_login(self, logins, cur_time):
#         """HELPER Method: Get the real login closest to cur_time."""
#         interarrival_col = 'closest_interarrival'
#         match = logins.copy()
#
#         match.loc[:, interarrival_col] = (match[LoginColumns.TIME] - cur_time).abs()
#         match = match.sort_values(by=interarrival_col)
#         match = match.head(1).drop(columns=[interarrival_col])
#
#         return match
#
#     def _get_synthetic_login_templates(self, logins, time, src, dst, user):
#         """HELPER Method: Get real logins so we have info to fill in for the synthetic event.
#
#         If the synthetic attack edge has not occurred,
#         piece together info from logins that involve the src/dst/user
#         of the synthetic login
#         """
#         closest_dst = self._get_closest_login(
#             logins[logins[LoginColumns.DST] == dst], time)
#
#         closest_src = self._get_closest_login(
#             logins[
#                 (logins[LoginColumns.SRC] == src) & (logins[LoginColumns.USER] == user)
#             ], time
#         )
#         if len(closest_src) > 0:
#             closest_user = closest_src
#         else:
#             print("Synthesizing login info: Unable to find a login with "
#                   "<src={}, user={}>, so synthesizing "
#                   "from disparate src, user, dst logins".format(src, user))
#             closest_src = self._get_closest_login(
#                 logins[logins[LoginColumns.SRC] == src], time)
#             closest_user = self._get_closest_login(
#                 logins[logins[LoginColumns.USER] == user], time)
#
#         return closest_src, closest_user, closest_dst
#
#     def _create_base_login_from_src(self, src_login):
#         """HELPER Method: Synthesize a skeleton login event that has some basic information."""
#         if src_login is None or len(src_login) == 0:
#             return None
#
#         base_login = src_login.copy()
#         keep_cols = [
#             LoginColumns.SRC, EnrichmentColumns.DEVICE_ID,
#             EnrichmentColumns.OPERATING_SYSTEM, EnrichmentColumns.BROWSER,
#             LoginColumns.DATASET
#         ]
#
#         for c in base_login.columns:
#             if c not in keep_cols:
#                 base_login.loc[:, c] = np.nan
#
#         return base_login
#
#     def _create_base_login_from_dst(self, dst_login, src):
#         """HELPER Method: Synthesize a skeleton login event that has some basic information."""
#         base_login = dst_login.copy()
#
#         src_cols = [LoginColumns.SRC,]
#
#         for c in src_cols:
#             base_login.loc[:, c] = src
#
#         base_login.loc[:, EnrichmentColumns.DEVICE_ID] = False
#         keep_cols = src_cols + [EnrichmentColumns.DEVICE_ID,]
#
#         for c in base_login.columns:
#             if c not in keep_cols:
#                 base_login.loc[:, c] = np.nan
#
#         return base_login
#
#     def _merge_into_new_login(self, base_login, src_login, dst_login, user_login):
#         """HELPER Method: Fill in a skeleton event with info from relevant real logins."""
#         attack = base_login.copy()
#
#         for c in [LoginColumns.DST, LoginColumns.PROTOCOL, LoginColumns.DATASET]:
#             if not dst_login.empty:
#                 attack[c] = dst_login[c].iloc[0]
#             else:
#                 attack[c] = np.nan
#
#         for c in [LoginColumns.USER]:
#             if not user_login.empty:
#                 attack[c] = user_login[c].iloc[0]
#             else:
#                 attack[c] = np.nan
#
#         return attack
#
#     def _format_synthetic_login(self, attack_df):
#         """HELPER Method: Finalize some fields for the synthetic login."""
#         attack = attack_df.copy()
#
#         attack.loc[:, EnrichmentColumns.MACHINE_AGE] = (
#             attack[LoginColumns.TIME] - attack[LoginColumns.TIME]
#         ).dt.total_seconds().copy()
#
#         attack.loc[:, LoginColumns.MOVEMENT_TYPE] = np.nan
#         movement_labeler = MovementLabeler()
#         attack = movement_labeler.label_movement(attack)
#
#         attack[LoginColumns.DATASET] = attack[LoginColumns.DATASET].astype(str)
#         attack.loc[:, LoginColumns.DATASET] = self.login_type
#
#         return attack
#
#
#
# if __name__ == '__main__':
#     # Testing the updated code
#     logins = pd.DataFrame({
#         'createdDateTime': [pd.Timestamp('2024-07-20 12:00:00'), pd.Timestamp('2024-07-20 13:00:00')],
#         'appId': ['app_1', 'app_2'],
#         'resourceId': ['resource_1', 'resource_2'],
#         'userPrincipalName': ['user1@example.com', 'user2@example.com'],
#         'deviceDetail.deviceId': ['device_1', 'device_2'],
#         'deviceDetail.operatingSystem': ['Windows', 'Linux'],
#         'deviceDetail.browser': ['Chrome', 'Firefox']
#     })
#
#     login_synthesizer = LoginSynthesizer()
#     synthesized_login = login_synthesizer.synthesize_login(
#         logins, pd.Timestamp('2024-07-20 14:00:00'), 'app_1', 'resource_5', 'user5@example.com'
#     )
#     print(synthesized_login.iloc[0])

import datetime
import pandas as pd
import numpy as np

from data_types import *
from utils import *

# Assuming LoginColumns, EnrichmentColumns, and MovementTypes are already defined and imported.

LOGIN_ANALYSIS_COLUMNS = [
    LoginColumns.TIME, LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER, EnrichmentColumns.SRC_SUBNET,LoginColumns.DATASET,LoginColumns.DAY_COL
]


class MovementLabeler(MovementTypes):
    """Class for labeling login movement types in Azure dataset."""
    def __init__(self):
        self.col = "MovementType"  # Column where the movement type will be labeled

    def label_movement_into_client(self, logins):
        """Label a login if it represents a move into a specific resource."""
        # Example logic: If a user accesses a new resource (resourceId)
        resource_access = logins.groupby([LoginColumns.USER, LoginColumns.DST]).cumcount() == 0
        logins.loc[resource_access, self.col] = self.MOVE_INTO_CLIENT
        return logins

    def label_movement_from_client(self, logins):
        """Label a login that represents a move from a specific resource."""
        unassigned = logins[self.col].isnull()
        resource_reuse = logins.groupby([LoginColumns.USER, LoginColumns.DST]).cumcount() > 0

        modify_mask = (unassigned & resource_reuse)
        logins.loc[modify_mask, self.col] = self.MOVE_FROM_CLIENT
        return logins

    def label_movement_from_server(self, logins):
        """Label a login if it represents a move from server to server."""
        unassigned = logins[self.col].isnull()
        server_mask = ~(logins.groupby([LoginColumns.USER, LoginColumns.DST]).cumcount() == 0)

        modify_mask = (unassigned & server_mask)
        logins.loc[modify_mask, self.col] = self.MOVE_FROM_SERVER
        return logins

    def label_movement(self, logins):
        """Label dataframe of logins."""
        if self.col not in logins.columns:
            logins[self.col] = np.nan

        logins[self.col] = logins[self.col].astype(object)  # Ensure the column type is compatible

        # Set aside any logins that already have movement labels
        movement_types = set([
            self.MOVE_FROM_CLIENT, self.MOVE_INTO_CLIENT,
            self.MOVE_FROM_SERVER
        ])
        labeled_logins_mask = logins[self.col].isin(movement_types)
        labeled_logins = logins[labeled_logins_mask]

        unlabeled_logins = logins[~labeled_logins_mask]
        unlabeled_logins = self.label_movement_into_client(unlabeled_logins)
        unlabeled_logins = self.label_movement_from_client(unlabeled_logins)
        unlabeled_logins = self.label_movement_from_server(unlabeled_logins)

        return pd.concat([labeled_logins, unlabeled_logins], sort=False)

class LoginSynthesizer:
    """Class for creating an artificial login event in Azure dataset."""
    DATASET_ATTACK_SUCCESS = 'attack:success'

    def __init__(self, login_type=None):
        if not login_type:
            login_type = self.DATASET_ATTACK_SUCCESS

        self.login_type = login_type

    def log(self, msg):
        """Helper Method: Log message depending on verbose or not."""
        print(msg)

    def synthesize_login(self, logins, time, src, dst, user):
        """MAIN METHOD: Create a fake login tuple with realistic attributes."""
        # Try to find a real login that matches the <src, dst, user> we're synthesizing
        attack_df = logins[
            (logins[LoginColumns.SRC] == src) &
            (logins[LoginColumns.DST] == dst) &
            (logins[LoginColumns.USER] == user)
        ]

        if len(attack_df) > 0:
            attack_df = self._get_closest_login(attack_df, time)
            self.log("Synthesizing login info:  Synthetic attack edge: "
                     "{} exists. Reusing.".format(
                attack_df.head(1)[LOGIN_ANALYSIS_COLUMNS].to_dict()
            ))
        else:
            closest_src, closest_user, closest_dst = self._get_synthetic_login_templates(
                logins, time, src, dst, user
            )
            self.log("Synthesizing login info: Constructing attack edge from SCRATCH:"
                     "\nsrc ({}) login: {}\ndst ({}) login: {}\nuser ({}) login: {}".format(
                src, closest_src[LOGIN_ANALYSIS_COLUMNS].to_dict(),
                dst, closest_dst[LOGIN_ANALYSIS_COLUMNS].to_dict(),
                user, closest_user[LOGIN_ANALYSIS_COLUMNS].to_dict(),
            ))

            base_login = self._create_base_login_from_src(closest_src)
            if base_login is None:
                base_login = self._create_base_login_from_dst(closest_dst, src)

            attack_df = self._merge_into_new_login(
                base_login, closest_src, closest_dst, closest_user)

        # Explicitly set these critical fields to ensure exact match with input
        attack_df.loc[:, LoginColumns.TIME] = time
        attack_df.loc[:, LoginColumns.SRC] = str(src)
        attack_df.loc[:, LoginColumns.DST] = str(dst)
        attack_df.loc[:, LoginColumns.USER] = str(user)

        # Update the inbound login count if DAY_COL is present
        if LoginColumns.DAY_COL in logins.columns:
            attack_df.loc[:, EnrichmentColumns.NUM_INBOUND_DAYS] = len(
                logins[logins[LoginColumns.DST] == src][LoginColumns.DAY_COL].drop_duplicates()
            )
        else:
            attack_df.loc[:, EnrichmentColumns.NUM_INBOUND_DAYS] = 0  # Default or another logic

        attack_df = self._format_synthetic_login(attack_df)

        return attack_df


    def _get_closest_login(self, logins, cur_time):
        """HELPER Method: Get the real login closest to cur_time."""
        interarrival_col = 'closest_interarrival'
        match = logins.copy()

        # Ensure the TIME column is a datetime format
        match[LoginColumns.TIME] = pd.to_datetime(match[LoginColumns.TIME], errors='coerce')

        # Perform the subtraction and handle NaT or NaN values gracefully
        match.loc[:, interarrival_col] = (match[LoginColumns.TIME] - cur_time).abs()

        # Drop any rows where the time difference could not be computed
        match = match.dropna(subset=[interarrival_col])

        # Sort by the computed time difference and return the closest login
        match = match.sort_values(by=interarrival_col)
        match = match.head(1).drop(columns=[interarrival_col])

        return match

    def _get_synthetic_login_templates(self, logins, time, src, dst, user):
        """HELPER Method: Get real logins so we have info to fill in for the synthetic event."""
        # src = src.split('_')[1]
        # dst = dst.split('_')[1]
        closest_dst = self._get_closest_login(
            logins[logins[LoginColumns.DST] == dst], time)
        closest_src = self._get_closest_login(
            logins[
                (logins[LoginColumns.SRC] == src) & (logins[LoginColumns.USER] == user)
            ], time
        )
        if len(closest_src) > 0:
            closest_user = closest_src
        else:
            print("Synthesizing login info: Unable to find a login with "
                  "<src={}, user={}>, so synthesizing "
                  "from disparate src, user, dst logins".format(src, user))
            closest_src = self._get_closest_login(
                logins[logins[LoginColumns.SRC] == src], time)
            closest_user = self._get_closest_login(
                logins[logins[LoginColumns.USER] == user], time)

        return closest_src, closest_user, closest_dst

    def _create_base_login_from_src(self, src_login):
        """HELPER Method: Synthesize a skeleton login event that has some basic information."""
        if src_login is None or len(src_login) == 0:
            return None

        base_login = src_login.copy()
        keep_cols = [
            LoginColumns.SRC, EnrichmentColumns.SRC_SUBNET,
            EnrichmentColumns.LOCATION, LoginColumns.DATASET
        ]

        # Explicitly handle boolean and integer columns before assigning NaN
        for c in base_login.columns:
            if c not in keep_cols:
                if pd.api.types.is_bool_dtype(base_login[c]):
                    base_login[c] = base_login[c].astype('object')  # Convert bool to object to allow NaN
                elif pd.api.types.is_integer_dtype(base_login[c]):
                    base_login[c] = base_login[c].astype('float64')  # Convert int to float64 to allow NaN
                base_login.loc[:, c] = np.nan

        return base_login

    def _create_base_login_from_dst(self, dst_login, src):
        """HELPER Method: Synthesize a skeleton login event that has some basic information."""
        base_login = dst_login.copy()

        src_cols = [LoginColumns.SRC]

        for c in src_cols:
            base_login.loc[:, c] = src

        base_login.loc[:, EnrichmentColumns.SRC_SUBNET] = False
        keep_cols = src_cols + [EnrichmentColumns.SRC_SUBNET]

        for c in base_login.columns:
            if c not in keep_cols:
                base_login.loc[:, c] = np.nan

        return base_login

    def _merge_into_new_login(self, base_login, src_login, dst_login, user_login):
        """HELPER Method: Fill in a skeleton event with info from relevant real logins."""
        attack = base_login.copy()

        for c in [LoginColumns.DST, LoginColumns.PROTOCOL, LoginColumns.DATASET]:
            if not dst_login.empty:
                attack[c] = dst_login[c].iloc[0]
            else:
                attack[c] = np.nan

        for c in [LoginColumns.USER]:
            if not user_login.empty:
                attack[c] = user_login[c].iloc[0]
            else:
                attack[c] = np.nan

        return attack

    def _format_synthetic_login(self, attack_df):
        """HELPER Method: Finalize some fields for the synthetic login."""
        if attack_df.empty:
            # Handle the case where attack_df is empty to prevent the error
            return attack_df

        attack = attack_df.copy()

        attack.loc[:, EnrichmentColumns.MACHINE_AGE] = (
                attack[LoginColumns.TIME] - attack[LoginColumns.TIME]
        ).dt.total_seconds().copy()

        # Ensure that the MovementType column is created only if attack_df is not empty
        if not attack.empty:
            attack.loc[:, "MovementType"] = np.nan
            movement_labeler = MovementLabeler()
            attack = movement_labeler.label_movement(attack)

        attack[LoginColumns.DATASET] = attack[LoginColumns.DATASET].astype(str)
        attack.loc[:, LoginColumns.DATASET] = self.login_type

        return attack


# class LoginSynthesizer:
#     """Class for creating an artificial login event in Azure dataset."""
#     DATASET_ATTACK_SUCCESS = 'attack:success'
#
#     def __init__(self, login_type=None):
#         if not login_type:
#             login_type = self.DATASET_ATTACK_SUCCESS
#
#         self.login_type = login_type
#
#     def log(self, msg):
#         """Helper Method: Log message depending on verbose or not."""
#         print(msg)
#
#     def synthesize_login(self, logins, time, src, dst, user):
#         """MAIN METHOD: Create a fake login tuple with realistic attributes."""
#         # Try to find a real login that matches the <src, dst, user> we're synthesizing
#         attack_df = logins[
#             (logins[LoginColumns.SRC] == src) &
#             (logins[LoginColumns.DST] == dst) &
#             (logins[LoginColumns.USER] == user)
#         ]
#
#         if len(attack_df) > 0:
#             # If the fake login has actually occurred,
#             # find the closest corresponding real login and copy over its information
#             attack_df = self._get_closest_login(attack_df, time)
#             self.log("Synthesizing login info:  Synthetic attack edge: "
#                      "{} exists. Reusing.".format(
#                 attack_df.head(1)[LOGIN_ANALYSIS_COLUMNS].to_dict()
#             ))
#         else:
#             # If the fake login's edge <src, dst, user> has never occurred,
#             # construct a fake login event by mashing together metadata
#             # from real logins that involved the src / dst / user separately
#             closest_src, closest_user, closest_dst = self._get_synthetic_login_templates(
#                 logins, time, src, dst, user
#             )
#             self.log("Synthesizing login info: Constructing attack edge from SCRATCH:"
#                      "\nsrc ({}) login: {}\ndst ({}) login: {}\nuser ({}) login: {}".format(
#                 src, closest_src[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#                 dst, closest_dst[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#                 user, closest_user[LOGIN_ANALYSIS_COLUMNS].to_dict(),
#             ))
#
#             # Create a dummy event that we will overwrite with the mash-up of login events above
#             base_login = self._create_base_login_from_src(closest_src)
#             if base_login is None:
#                 # However, we might have selected a src that's never launched logins,
#                 # in this case, take the dst login and do some extra work to format.
#                 base_login = self._create_base_login_from_dst(closest_dst, src)
#
#             # Overwrite the dummy event's attributes with the mash-up of src/dst/user login events
#             attack_df = self._merge_into_new_login(
#                 base_login, closest_src, closest_dst, closest_user)
#
#         # Set the fake login's time to the specified time
#         attack_df.loc[:, LoginColumns.TIME] = time
#         attack_df.loc[:, LoginColumns.TIME] = pd.to_datetime(
#             attack_df[LoginColumns.TIME]).copy()
#
#         # Ensure these critical fields are set correctly
#         attack_df.loc[:, LoginColumns.SRC] = src
#         attack_df.loc[:, LoginColumns.DST] = dst
#         attack_df.loc[:, LoginColumns.USER] = user
#
#         # Update the inbound login count to this src based on global history
#         attack_df.loc[:, EnrichmentColumns.NUM_INBOUND_DAYS] = len(
#             logins[logins[LoginColumns.DST] == src][LoginColumns.DAY_COL].drop_duplicates()
#         )
#
#         # Set some final fields for the fake login event to make clear it's a fake / attack event
#         attack_df = self._format_synthetic_login(attack_df)
#
#         return attack_df
#
#     def _get_closest_login(self, logins, cur_time):
#         """HELPER Method: Get the real login closest to cur_time."""
#         interarrival_col = 'closest_interarrival'
#         match = logins.copy()
#         print(cur_time)
#         match.loc[:, interarrival_col] = (match[LoginColumns.TIME] - cur_time).abs()
#         match = match.sort_values(by=interarrival_col)
#         match = match.head(1).drop(columns=[interarrival_col])
#
#         return match
#
#     def _get_synthetic_login_templates(self, logins, time, src, dst, user):
#         """HELPER Method: Get real logins so we have info to fill in for the synthetic event."""
#         closest_dst = self._get_closest_login(
#             logins[logins[LoginColumns.DST] == dst], time)
#
#         closest_src = self._get_closest_login(
#             logins[
#                 (logins[LoginColumns.SRC] == src) & (logins[LoginColumns.USER] == user)
#             ], time
#         )
#         if len(closest_src) > 0:
#             closest_user = closest_src
#         else:
#             print("Synthesizing login info: Unable to find a login with "
#                   "<src={}, user={}>, so synthesizing "
#                   "from disparate src, user, dst logins".format(src, user))
#             closest_src = self._get_closest_login(
#                 logins[logins[LoginColumns.SRC] == src], time)
#             closest_user = self._get_closest_login(
#                 logins[logins[LoginColumns.USER] == user], time)
#
#         return closest_src, closest_user, closest_dst
#
#     def _create_base_login_from_src(self, src_login):
#         """HELPER Method: Synthesize a skeleton login event that has some basic information."""
#         if src_login is None or len(src_login) == 0:
#             return None
#
#         base_login = src_login.copy()
#         keep_cols = [
#             LoginColumns.SRC, EnrichmentColumns.SRC_SUBNET,
#             EnrichmentColumns.LOCATION, LoginColumns.DATASET
#         ]
#
#         for c in base_login.columns:
#             if c not in keep_cols:
#                 base_login.loc[:, c] = np.nan
#
#         return base_login
#
#     def _create_base_login_from_dst(self, dst_login, src):
#         """HELPER Method: Synthesize a skeleton login event that has some basic information."""
#         base_login = dst_login.copy()
#
#         src_cols = [LoginColumns.SRC]
#
#         for c in src_cols:
#             base_login.loc[:, c] = src
#
#         base_login.loc[:, EnrichmentColumns.SRC_SUBNET] = False
#         keep_cols = src_cols + [EnrichmentColumns.SRC_SUBNET]
#
#         for c in base_login.columns:
#             if c not in keep_cols:
#                 base_login.loc[:, c] = np.nan
#
#         return base_login
#
#     def _merge_into_new_login(self, base_login, src_login, dst_login, user_login):
#         """HELPER Method: Fill in a skeleton event with info from relevant real logins."""
#         attack = base_login.copy()
#
#         for c in [LoginColumns.DST, LoginColumns.PROTOCOL, LoginColumns.DATASET]:
#             if not dst_login.empty:
#                 attack[c] = dst_login[c].iloc[0]
#             else:
#                 attack[c] = np.nan
#
#         for c in [LoginColumns.USER]:
#             if not user_login.empty:
#                 attack[c] = user_login[c].iloc[0]
#             else:
#                 attack[c] = np.nan
#
#         return attack
#
#     def _format_synthetic_login(self, attack_df):
#         """HELPER Method: Finalize some fields for the synthetic login."""
#         attack = attack_df.copy()
#
#         attack.loc[:, EnrichmentColumns.MACHINE_AGE] = (
#             attack[LoginColumns.TIME] - attack[LoginColumns.TIME]
#         ).dt.total_seconds().copy()
#
#         attack.loc[:, "MovementType"] = np.nan
#         movement_labeler = MovementLabeler()
#         attack = movement_labeler.label_movement(attack)
#
#         attack[LoginColumns.DATASET] = attack[LoginColumns.DATASET].astype(str)
#         attack.loc[:, LoginColumns.DATASET] = self.login_type
#
#         return attack


if __name__ == '__main__':

    login_synthesizer = LoginSynthesizer()
    # Timestamp('2022-04-11 02:58:40.198150900+0000', tz='UTC')
    synthesized_login = login_synthesizer.synthesize_login(
        df_signin, pd.Timestamp('2022-04-11 02:58:40.198150900+0000',tz='UTC'), 'A001', 'R001', 'U002'
    )
    print(synthesized_login.iloc[0])
