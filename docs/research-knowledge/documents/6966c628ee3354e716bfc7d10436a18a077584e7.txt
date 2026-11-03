# Fee-cap row reporting correction

Independent review found that the01–03 calculator returned a failing row's
next required fee together with the preceding evaluated fee's mass/storage.
For example, a20M shared reserve remainder at500 reported fee53,587,000 with
storage107,174, although that storage was evaluated at the previous fee.
The over-cap rejection remained correct; the tuple was not coherent.

The original outputs remain byte-identical. `history/cost_envelope-03.py`
retains the reviewed03 source and matches its recorded calculator SHA.
`cost-envelope-04.json` separates the evaluated fee, its metrics and the next
required fee above the cap. Positive fees/masses, economic pass/fail outcomes,
permission bounds and Ba/Bp allocations are unchanged. It also labels the
current1700/prospective1600 ADMIT atoms and unchanged fixed authorized fees.
No native transaction or proof was generated or rerun for this correction.
