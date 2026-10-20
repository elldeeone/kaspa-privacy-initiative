"""Replay an incomplete H18 observation with the same rules and one worker.

The initial two-worker CP-SAT run exhausted host memory on one query. A
captured identical model solved in 0.16 seconds with one worker. This changes
search scheduling only: constraints, objectives, certificates and the
requirement for complete inference remain in scheduled_payout_observer.
Record this wrapper's hash alongside the original observer source hashes.
"""
from ortools.sat.python import cp_model


def enable():
    original = cp_model.CpSolver.solve

    def single_worker(self, model, *args, **kwargs):
        self.parameters.num_search_workers = 1
        return original(self, model, *args, **kwargs)

    cp_model.CpSolver.solve = single_worker


if __name__ == "__main__":
    import scheduled_payout_observer

    enable()
    scheduled_payout_observer.main()
