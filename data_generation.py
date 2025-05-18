import json
import os
import random
from collections.abc import Sequence
from typing import Any

import apache_beam as beam
from apache_beam.coders import VarIntCoder
from apache_beam.options.pipeline_options import PipelineOptions
from apache_beam.transforms.periodicsequence import PeriodicImpulse
from apache_beam.transforms.userstate import ReadModifyWriteStateSpec
from apache_beam.transforms.window import FixedWindows
from dotenv import load_dotenv
from faker import Faker

load_dotenv()

# Initialize Faker
fake = Faker()


def generate_simulation_data(access_type: str) -> dict:
    """
    Generates simulated data based on the access type.

    The function simulates user activity metrics (reads, edits, downloads, encryptions)
    based on predefined access levels: "no_access", "reader", or "editor".
    Each metric is generated from a normal distribution with specified means and
    standard deviations, ensuring results are non-negative integers.

    Args:
        access_type: A string indicating the type of access.
                     Expected values: "no_access", "reader", "editor".

    Returns:
        A dictionary containing the simulated data:
        {
            "user_name": str,      # Simulated user name
            "access_type": str,    # The input access type
            "num_read": int,       # Simulated number of reads
            "num_edits": int,      # Simulated number of edits
            "num_downloads": int,  # Simulated number of downloads
            "num_encryption": int  # Simulated number of encryptions
        }

    Raises:
        ValueError: If an unknown access_type is provided.
    """
    # Initialize all metrics to 0
    num_read = 0
    num_edits = 0
    num_downloads = 0
    num_encryption = 0

    # Rule 1: No access
    if access_type == "no_access":
        # All metrics remain 0, so no action needed here.
        pass
    # Rule 2: Reader access
    elif access_type == "reader":
        # num_read is N(100, 50)
        num_read = max(0, round(random.normalvariate(100, 50)))
        # num_downloads is N(10, 5)
        num_downloads = max(0, round(random.normalvariate(10, 5)))
        # num_edits and num_encryption remain 0 for "reader"
    # Rule 3: Editor access
    elif access_type == "editor":
        # num_read is N(10, 10)
        num_read = max(0, round(random.normalvariate(10, 10)))
        # num_edits is N(200, 100)
        num_edits = max(0, round(random.normalvariate(200, 100)))
        # num_downloads is N(5, 2)
        num_downloads = max(0, round(random.normalvariate(5, 2)))
        # num_encryption is N(10, 10)
        num_encryption = max(0, round(random.normalvariate(10, 10)))
    # Handle unknown access types
    else:
        raise ValueError(
            f"Unknown access_type: '{access_type}'. "
            "Expected 'no_access', 'reader', or 'editor'."
        )

    # Return the generated data as a dictionary
    return {
        "user_name": fake.user_name(),
        "access_type": access_type,
        "num_read": num_read,
        "num_edits": num_edits,
        "num_downloads": num_downloads,
        "num_encryption": num_encryption
    }


def generate_anomaly_data(access_type: str) -> dict:
    """
    Generates anomalous simulated data based on the access type.

    This function creates data points that deviate from the normal patterns
    defined in `generate_simulation_data`, using different fixed distributions.

    Args:
        access_type: A string indicating the type of access for which to generate an anomaly.
                     Expected values: "no_access", "reader", "editor".

    Returns:
        A dictionary containing the anomalous simulated data.
        Structure is the same as `generate_simulation_data`.

    Raises:
        ValueError: If an unknown access_type is provided.
    """
    num_read = 0
    num_edits = 0
    num_downloads = 0
    num_encryption = 0

    if access_type == "no_access":
        # Anomaly: Some unexpected activity
        num_read = max(0, round(random.normalvariate(5, 2)))  # Small number of reads
        num_edits = max(0, round(random.normalvariate(3, 1)))  # Small number of edits
        # num_downloads and num_encryption remain 0 or very low
        num_downloads = 0
        num_encryption = 0
    elif access_type == "reader":
        # Anomaly: Unusually high activity or unexpected actions
        num_read = max(0, round(random.normalvariate(350, 50)))  # Very high reads
        num_edits = max(0, round(random.normalvariate(20, 5)))  # Edits, normally 0
        num_downloads = max(0, round(random.normalvariate(75, 15)))  # Very high downloads
        num_encryption = max(0, round(random.normalvariate(10, 3)))  # Encryptions, normally 0
    elif access_type == "editor":
        # Anomaly: Unusual pattern of activity for an editor
        num_read = max(0, round(random.normalvariate(150, 30)))  # High reads (normally low for editor)
        num_edits = max(0, round(random.normalvariate(25, 10)))  # Low edits (normally high)
        num_downloads = max(0, round(random.normalvariate(50, 10)))  # High downloads
        num_encryption = max(0, round(random.normalvariate(70, 20)))  # Very high encryptions
    else:
        raise ValueError(
            f"Unknown access_type for anomaly: '{access_type}'. "
            "Expected 'no_access', 'reader', or 'editor'."
        )

    return {
        "user_name": fake.user_name(),
        "access_type": access_type,  # Mark as anomaly
        "num_read": num_read,
        "num_edits": num_edits,
        "num_downloads": num_downloads,
        "num_encryption": num_encryption
    }


# Main block for example usage (this will run when the script is executed directly)
dataset = []
# Define the number of samples for each access type
access_types_to_simulate_for_normal = (["no_access"] * 20 +
                                      ["reader"] * 20 +
                                      ["editor"] * 20)
# Define the number of samples for each access type
access_types_to_simulate_for_anomaly = (["no_access"] * 20 +
                                       ["reader"] * 20 +
                                       ["editor"] * 20)

access_types_to_simulate = access_types_to_simulate_for_normal + access_types_to_simulate_for_anomaly

random.shuffle(access_types_to_simulate)  # Shuffle to mix the types

for acc_type in access_types_to_simulate:
    dataset.append(generate_simulation_data(acc_type))


class SequenceToPeriodicStream(beam.PTransform):
    """ A streaming source that generate periodic event based on a given sequence. """
    def __init__(self, data: Sequence[Any], delay: float = 0.1, repeat: bool = True):
        self._data = data
        self._delay = delay
        self._repeat = repeat

    class EmitOne(beam.DoFn):
        INDEX_SPEC = ReadModifyWriteStateSpec('index', VarIntCoder())

        def __init__(self, data, repeat):
            self._data = data
            self._repeat = repeat
            self._max_index = len(self._data)

        def process(self, element, model_state=beam.DoFn.StateParam(INDEX_SPEC)):
            index = model_state.read() or 0
            if index >= self._max_index:
                return

            yield self._data[index]

            index += 1
            if self._repeat:
                index %= self._max_index
            model_state.write(index)

    def expand(self, input):
        return (
            input | PeriodicImpulse(fire_interval=self._delay)
            | beam.Map(lambda x: (0, x))
            | beam.ParDo(SequenceToPeriodicStream.EmitOne(self._data, self._repeat))
            | beam.WindowInto(FixedWindows(self._delay)))


TEMP_LOCATION = os.environ["GCS_ROOT"] + '/data-generation/tmp'
STAGING_LOCATION = os.environ["GCS_ROOT"] + '/data-generation/staging'

options = PipelineOptions([
    "--runner=DataflowRunner",
    "--temp_location=" + TEMP_LOCATION,
    "--staging_location=" + STAGING_LOCATION,
    "--project=" + os.environ["GOOGLE_CLOUD_PROJECT"],
    "--region=" + os.environ["GOOGLE_CLOUD_LOCATION"]
])

with beam.Pipeline(options=options) as p:
    _ = (p
         | "SequenceToPeriodicStream" >> SequenceToPeriodicStream(dataset, delay=1, repeat=True)
         | "JsonifyInput" >> beam.Map(lambda x: json.dumps(x).encode("utf-8"))
         | beam.io.gcp.pubsub.WriteToPubSub(topic=os.environ["PUBSUB_TOPIC"])
    )