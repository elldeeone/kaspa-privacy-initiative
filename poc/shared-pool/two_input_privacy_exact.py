"""Exact integer feasibility via relaxed graph search plus integer verification.

A rational relaxation can prove infeasibility. A positive answer is accepted
only after the original CP-SAT integer relation validates the complete selected
graph. If it rejects, block that graph and continue: never count a relaxation
alone as an integer solution. Public-data SAT witnesses also cache answers to
other targets, without consulting truth.
"""
import z3
from two_input_privacy_z3 import Z3Model


class ExactModel:
    def __init__(self,data,floor=60_000_000,payout_floor=10_000_000):
        from two_input_privacy_observer import Model
        self.relaxed=Z3Model(data,floor,payout_floor,relaxed=True)
        self.integer=Model(data,floor,payout_floor)
        self.data=data;self.births=self.integer.births;self.upper=self.integer.upper
        self.feasible={i:set() for i in self.integer.select}
        self.queries=0;self.integer_certificates=0;self.rejected_relaxations=0

    def check(self,target=None,combo=None):
        if target is not None and tuple(combo) in self.feasible[target]:return True
        while True:
            self.queries+=1
            if not self.relaxed.check(target,combo):return False
            witness=self.relaxed.solver.model()
            graph={i:tuple(p for p,s in enumerate(ss) if z3.is_true(witness.eval(s,model_completion=True)))
                   for i,ss in self.relaxed.select.items()}
            if self.integer.check(fixed=graph):
                self.integer_certificates+=1
                for i,c in graph.items():self.feasible[i].add(c)
                return True
            # This complete graph has no integer realization. Reject it globally;
            # other graphs for the same queried candidate remain searchable.
            self.rejected_relaxations+=1
            self.relaxed.solver.add(z3.Or([z3.Not(s) if p in graph[i] else s
                for i,ss in self.relaxed.select.items() for p,s in enumerate(ss)]))

    def candidates(self,target,allowed=None):
        from two_input_privacy_observer import possibilities
        return [c for c in (possibilities(self.data['events'][target]) if allowed is None else allowed) if self.check(target,c)]
