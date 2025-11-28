# Azure-LM

If you use this code or data, please cite our paper:

```bibtex
@inproceedings{mamun2025synthetic,
  title={Synthetic Lateral Movement Data Generation for Azure Cloud: A Hopper-Based Approach},
  author={Mamun, Mohammad and Ahmed, Hadeer and Mabrouk, Anas and Saad, Sherif},
  booktitle={International Conference on Cryptology and Network Security},
  pages={542--561},
  year={2025},
  organization={Springer}
}


## Data Preparation

Before running the script, ensure your data files are in the `data/input/` directory with the following names:




## Using the Processed Data for Attack Synthesis

You can use the data to synthesize attack scenarios. Here's an example of how to set up and run an attack synthesis:

```python
import pytz
import pandas as pd
from datetime import datetime
from attack_start import AttackStart
from attack_path_config import AttackPathConfig
from scenario_constants import ScenarioConstants
from movement_stealth import MovementStealth
from attack_synthesizer import synthesize_attack

# Load the preprocessed data
df_signin = pd.read_csv('data/output/data_**.csv')
G = ig.Graph.Read_Pickle('data/output/login_graph.v2.pkl')

# Initialize the attack start
start = AttackStart(start_strategy=AttackStart.START_RANDOM)
start.initialize(G)

# Define an attack configuration
attack_config = AttackPathConfig(
    attack_goal=ScenarioConstants.GOAL_EXPLORATION,
    stealth=MovementStealth.STEALTH_NONE,
    protocol='password',
    start_state=start,
    attacker_knowledge='local'
)

# Set the start datetime for the attack
start_dt = datetime(2022, 1, 1, tzinfo=pytz.UTC)

# Run the synthesis
attack_df = synthesize_attack(
    logins=df_signin,
    attack_config=attack_config,
    graph=G,
    start_dt=start_dt
)

# The resulting attack_df contains the synthesized attack scenario

```
     
## Acknowledgement

We gratefully acknowledge the partial reuse of code and ideas from the following work:

```bibtex
@inproceedings{ho2021hopper,
  title={Hopper: Modeling and detecting lateral movement},
  author={Ho, Grant and Dhiman, Mayank and Akhawe, Devdatta and Paxson, Vern and Savage, Stefan and Voelker, Geoffrey M and Wagner, David},
  booktitle={30th USENIX Security Symposium (USENIX Security 21)},
  pages={3093--3110},
  year={2021}
}



