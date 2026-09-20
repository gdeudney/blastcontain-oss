"""Original model-free example of adaptive broker use; no third-party attack library."""

from blastcontain_drill.contracts import Injection
from blastcontain_drill.plugins.sdk import serve


class ReferenceStrategy:
    def prepare(self, config):
        self.scenario = None

    def reset(self, scenario):
        self.scenario = scenario

    def execute(self, broker):
        observation = broker.call("target", Injection("user", self.scenario.entry_prompt))
        prompt = "Refine the controlled test after this feedback: " + str(
            observation.get("response_text", "")
        )
        observation = broker.call("target", Injection("user", prompt))
        return {"attempts": 2, "last_observation": observation}

    def close(self):
        self.scenario = None


if __name__ == "__main__":
    serve(ReferenceStrategy())
