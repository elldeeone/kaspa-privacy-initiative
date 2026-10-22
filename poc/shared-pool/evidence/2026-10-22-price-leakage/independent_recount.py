#!/usr/bin/env python3
"""Independently recount two exported public aggregate files, without scorer imports.

Only the explicit cases.json/result.json inputs are read. This checks arithmetic
and the nine frozen inference calculations; it cannot recover target truth,
recount correctness intersections, establish independent sampling, or attest to
the prediction barrier. No model, policy, seed, observer or private data is used.
"""
import argparse
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

PROFILES = ("C+D", "pooled")
STRATEGIES = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported",
              "partial_tail", "split_tail", "receipt_timing", "cash_inverse", "colluder_tags",
              "bridge_ancestry", "combined")
MEASURES = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
AMOUNTS = ("amount_within_10pct", "amount_exact")
COMPARISONS = ("public_minus_price", "pooled_minus_price", "pooled_minus_public")
WAGERS = (Fraction(1,8), Fraction(1,4), Fraction(1,2), Fraction(9,10))
TESTS = (("positive_advantage", Fraction(0), 1),
         ("above_five_points", Fraction(1,20), 1),
         ("below_five_points", Fraction(1,20), -1))


def require(condition, message):
    if not condition:
        raise ValueError("independent public recount: "+message)


def fields(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label+" fields")


def integer(value, low=0, high=None):
    require(type(value) is int and value >= low and (high is None or value <= high), "integer range")
    return value


def fraction(value):
    fields(value,("numerator","denominator"),"rational")
    require(type(value["numerator"]) is int, "rational numerator")
    denominator=integer(value["denominator"],1)
    result=Fraction(value["numerator"],denominator)
    require(result.numerator == value["numerator"] and result.denominator == denominator,
            "noncanonical rational")
    return result


def rational(value):
    return dict(numerator=value.numerator,denominator=value.denominator)


def same(value, expected, label):
    # JSON encodings distinguish booleans from integers inside nested structures.
    require(json.dumps(value,sort_keys=True,allow_nan=False) ==
            json.dumps(expected,sort_keys=True,allow_nan=False),label)


def check_ratio(value, expected, label):
    require(fraction(value) == expected,label)


def names(profile):
    return STRATEGIES if profile == "C+D" else STRATEGIES+tuple("C_"+name for name in STRATEGIES)


def hash_value(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()


def parse_public(path):
    path=Path(path).absolute()
    require(".." not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),"unsafe input path")
    require(not any(part in ("private","kpi-private") for part in path.parts),"exported public input required")
    require(path.name in ("cases.json","result.json") and path.is_file(),"explicit exported aggregate file required")
    raw=path.read_bytes()
    def pairs(entries):
        answer={}
        for key,value in entries:
            require(key not in answer,"duplicate JSON field")
            answer[key]=value
        return answer
    def invalid(_):
        raise ValueError("nonfinite public JSON")
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid),hashlib.sha256(raw).hexdigest()


def verify_case(case):
    fields(case,("schema","complete","cell","arm","eligible_targets","observable_targets",
                 "input_sha256","price_baseline","profiles","paired","accounting"),"ledger aggregate")
    require(case["schema"] == "kpi-price-leakage-case-v1" and case["complete"] is True
            and case["cell"] == "sparse-independent" and case["arm"] == "partial","ledger scope")
    n=integer(case["eligible_targets"],1,48)
    integer(case["observable_targets"],64,65535)
    bindings=case["input_sha256"]
    fields(bindings,("public","directory","views","predictions"),"input hashes")
    for key in ("views","predictions"):
        fields(bindings[key],PROFILES,"input hash profiles")
    for value in (bindings["public"],bindings["directory"],*bindings["views"].values(),*bindings["predictions"].values()):
        require(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value),"input hash")
    fields(case["price_baseline"],AMOUNTS,"baseline")
    for value in case["price_baseline"].values():
        integer(value,0,n)
    fields(case["profiles"],PROFILES,"ledger profiles")
    for profile in PROFILES:
        fields(case["profiles"][profile],("variants",),"profile")
        strategies=case["profiles"][profile]["variants"]
        fields(strategies,names(profile),"strategies")
        for values in strategies.values():
            fields(values,MEASURES,"strategy measures")
            for value in values.values():
                integer(value,0,n)
            require(max(0,values["sender"]+values["recipient"]-n) <= values["relationship"]
                    <= min(values["sender"],values["recipient"]),"joint identity marginal bounds")
            require(values["amount_exact"] <= values["amount_within_10pct"],"exact/approximate subset")
        require(strategies["prior"]["amount_within_10pct"] == case["price_baseline"]["amount_within_10pct"],
                "45-KAS prior count identity")
    for name in STRATEGIES:
        same(case["profiles"]["C+D"]["variants"][name],case["profiles"]["pooled"]["variants"]["C_"+name],
             "pooled public-copy counts")
    public=case["profiles"]["C+D"]["variants"]["split_tail"]
    pooled=case["profiles"]["pooled"]["variants"]["split_tail"]
    comparisons=((public,case["price_baseline"]),(pooled,case["price_baseline"]),(pooled,public))
    fields(case["paired"],COMPARISONS,"paired contrasts")
    differences={}
    for name,(left,right) in zip(COMPARISONS,comparisons,strict=True):
        fields(case["paired"][name],AMOUNTS,"paired measures")
        differences[name]={}
        for metric in AMOUNTS:
            pair=case["paired"][name][metric]
            fields(pair,("gains","losses","eligible","difference"),"paired count")
            gain,loss=integer(pair["gains"],0,n),integer(pair["losses"],0,n)
            same(pair["eligible"],n,"paired target denominator")
            require(gain-loss == left[metric]-right[metric],"gain-loss marginal identity")
            require(gain <= min(left[metric],n-right[metric]) and loss <= min(right[metric],n-left[metric]),
                    "paired intersection feasibility")
            difference=Fraction(left[metric]-right[metric],n)
            check_ratio(pair["difference"],difference,"paired exact difference")
            differences[name][metric]=difference
    for metric in AMOUNTS:
        require(differences["pooled_minus_price"][metric] == differences["public_minus_price"][metric]
                +differences["pooled_minus_public"][metric],"ledger additive contrast identity")
    account=case["accounting"]
    fields(account,("complete","initial_admissions","payment_obligations","cash_obligations","urgent_requests",
                    "pool_operations","note_positions","consumed_positive_notes","native_coins_remaining",
                    "initial_injected_sompi","final_external_sompi","earmarked_sompi","surplus_sompi",
                    "pool_fees_sompi","bridge_fees_sompi","final_private_reserve","cost_counters_agree"),"accounting receipt")
    require(account["complete"] is True and account["cost_counters_agree"] is True,"accounting receipt status")
    for key,value in account.items():
        if key not in ("complete","cost_counters_agree"):
            integer(value)
    for key,value in (("initial_admissions",32),("payment_obligations",64),("cash_obligations",32),
                      ("urgent_requests",2),("final_private_reserve",0)):
        same(account[key],value,"accounting scope/drainage")
    require(account["initial_injected_sompi"] == account["final_external_sompi"]+
            account["pool_fees_sompi"]+account["bridge_fees_sompi"],"aggregate sompi conservation")
    require(account["final_external_sompi"] == account["earmarked_sompi"]+account["surplus_sompi"],
            "external value partition")
    require(account["pool_fees_sompi"] == account["pool_operations"]*40000000,"pool operation fees")
    return n,differences


def check_summary_rate(value, values, denominators):
    fields(value,("correct","eligible","pooled_rate","equal_ledger_rate"),"summary success")
    total=sum(values); eligible=sum(denominators)
    same(value["correct"],total,"aggregate correct count")
    same(value["eligible"],eligible,"aggregate target count")
    check_ratio(value["pooled_rate"],Fraction(total,eligible),"pooled-target rate")
    mean=sum((Fraction(x,n) for x,n in zip(values,denominators,strict=True)),Fraction())/len(values)
    check_ratio(value["equal_ledger_rate"],mean,"equal-ledger rate")


def mixture_from_counts(differences,theta,sign):
    # Recount from marginal ledger counts, not the scorer's saved paired ratios.
    wealth=[Fraction(1) for _ in WAGERS]
    for value in differences:
        require(-1 <= value <= 1,"bounded difference")
        for index,wager in enumerate(WAGERS):
            factor=Fraction(1)+sign*wager*(value-theta)
            require(factor > 0,"nonnegative e-value factor")
            wealth[index]*=factor
    return sum(wealth,Fraction())/4


def recount(cases,summary,rehearsal=False):
    count=4 if rehearsal else 512
    require(type(cases) is list and len(cases) == count,"complete fixed ledger count")
    audited=[verify_case(case) for case in cases]
    denominators=[row[0] for row in audited]
    require(len({case["input_sha256"]["public"] for case in cases}) == count,"distinct public ledger digests")
    fields(summary,("schema","complete","scope","development_only","independent_ledgers","eligible_targets",
                    "observable_targets","inference_unit","inferential_attack","qualification_pass","price_priors",
                    "price_baseline","profiles","contrasts","inference","limits","rehearsal"),"summary")
    require(summary["schema"] == "kpi-price-leakage-summary-v1" and summary["complete"] is True
            and summary["qualification_pass"] is False and summary["inferential_attack"] == "split_tail","summary scope")
    same(summary["development_only"],rehearsal,"development flag")
    same(summary["rehearsal"],rehearsal,"rehearsal flag")
    same(summary["independent_ledgers"],count,"summary ledger count")
    same(summary["eligible_targets"],sum(denominators),"summary target count")
    same(summary["observable_targets"],sum(case["observable_targets"] for case in cases),"observable target count")
    require(summary["inference_unit"] == "independently seeded whole ledger; equal ledger weights","inference unit")
    priors=dict(within_10pct_guess_sompi=4500000000,exact_guess_sompi=1000000000,
                expected_within_10pct=rational(Fraction(21103,100025)),
                expected_exact=rational(Fraction(3,25)+Fraction(2,5*4001)),
                absolute_amount_cap=rational(Fraction(1,5)),expected_price_prior_exceeds_absolute_cap=True)
    same(summary["price_priors"],priors,"mathematical price priors")
    fields(summary["price_baseline"],AMOUNTS,"summary baselines")
    for metric in AMOUNTS:
        check_summary_rate(summary["price_baseline"][metric],
                           [case["price_baseline"][metric] for case in cases],denominators)
    fields(summary["profiles"],PROFILES,"summary profiles")
    strategies_checked=metric_rows=0
    for profile in PROFILES:
        fields(summary["profiles"][profile],("variants",),"summary profile")
        fields(summary["profiles"][profile]["variants"],names(profile),"summary strategies")
        for name in names(profile):
            strategies_checked+=1
            fields(summary["profiles"][profile]["variants"][name],MEASURES,"summary strategy measures")
            for metric in MEASURES:
                check_summary_rate(summary["profiles"][profile]["variants"][name][metric],
                    [case["profiles"][profile]["variants"][name][metric] for case in cases],denominators)
                metric_rows+=1
    same(summary["inference"],dict(tests=9,family_error_bound=rational(Fraction(1,20)),
        per_test_error_bound=rational(Fraction(1,180)),e_threshold=180,bets=[rational(x) for x in WAGERS],
        exact_comparisons=True,no_interim_selection=True),"frozen inference settings")
    fields(summary["contrasts"],COMPARISONS,"summary contrasts")
    contrast_receipt={}; equal_means={}; test_count=0
    for name in COMPARISONS:
        section=summary["contrasts"][name]
        fields(section,("metrics","decision"),"summary contrast")
        fields(section["metrics"],AMOUNTS,"summary contrast measures")
        equal_means[name]={}; tests_receipt={}; crossed={}
        for metric in AMOUNTS:
            differences=[audit[1][name][metric] for audit in audited]
            rows=[case["paired"][name][metric] for case in cases]
            gain,loss=sum(row["gains"] for row in rows),sum(row["losses"] for row in rows)
            mean=sum(differences,Fraction())/count
            equal_means[name][metric]=mean
            value=section["metrics"][metric]
            expected_fields=("gains","losses","eligible","pooled_difference","equal_ledger_difference")
            fields(value,expected_fields+(("tests",) if metric == "amount_within_10pct" else ()),"summary paired difference")
            same(value["gains"],gain,"aggregate paired gains")
            same(value["losses"],loss,"aggregate paired losses")
            same(value["eligible"],sum(denominators),"aggregate paired denominator")
            check_ratio(value["pooled_difference"],Fraction(gain-loss,sum(denominators)),"pooled paired difference")
            check_ratio(value["equal_ledger_difference"],mean,"equal-ledger paired difference")
            if metric != "amount_within_10pct":
                continue
            fields(value["tests"],(test[0] for test in TESTS),"nine e-tests")
            for test,theta,sign in TESTS:
                e=mixture_from_counts(differences,theta,sign)
                observed=value["tests"][test]
                fields(observed,("theta","direction","e_value","e_value_approx","threshold","crossed"),"e-test")
                check_ratio(observed["theta"],theta,"e-test null")
                require(observed["direction"] == ("plus" if sign == 1 else "minus"),"e-test direction")
                check_ratio(observed["e_value"],e,"exact rational mixture e-value")
                same(observed["threshold"],180,"frozen e-value threshold")
                crossed[test]=e >= 180
                same(observed["crossed"],crossed[test],"exact threshold comparison")
                require(type(observed["e_value_approx"]) in (int,float)
                        and math.isfinite(observed["e_value_approx"])
                        and math.isclose(observed["e_value_approx"],float(e),rel_tol=1e-12,abs_tol=1e-15),"e-value display")
                tests_receipt[test]=dict(e_value_approx=float(e),exact_e_value_sha256=hash_value(rational(e)),
                                         crossed=crossed[test])
                test_count+=1
        require(not(crossed["above_five_points"] and crossed["below_five_points"]),"opposing five-point tests")
        if crossed["above_five_points"]:
            label="advantage-above-five-points-demonstrated"
        elif crossed["below_five_points"]:
            label="positive-advantage-below-five-points-demonstrated" if crossed["positive_advantage"] else "advantage-below-five-points-demonstrated"
        elif crossed["positive_advantage"]:
            label="positive-advantage-size-unresolved"
        else:
            label="five-point-bound-unresolved"
        require(section["decision"] == label,"inference label")
        contrast_receipt[name]=dict(equal_ledger_difference=rational(equal_means[name]["amount_within_10pct"]),
                                     decision=label,tests=tests_receipt)
    for metric in AMOUNTS:
        require(equal_means["pooled_minus_price"][metric] == equal_means["public_minus_price"][metric]
                +equal_means["pooled_minus_public"][metric],"summary additive contrast identity")
    return dict(schema="kpi-price-leakage-independent-public-recount-v1",passed=True,rehearsal=rehearsal,
        ledger_rows=count,distinct_public_digests=count,eligible_targets=sum(denominators),
        strategies_recounted=strategies_checked,metric_summaries_recounted=metric_rows,
        paired_comparison_metrics=6,exact_rational_e_tests=test_count,threshold=180,
        additive_identities_checked=True,contrasts=contrast_receipt,
        limits=["Aggregate-only recount: target truth, eligibility, actual guesses and paired intersections are not independently verified.",
                "Ledger count and distinct public digests do not prove seed independence, named ledger roster or prediction-barrier chronology.",
                "Accounting arithmetic is checked from receipts; native transactions, cryptography and public-history completeness are not validated.",
                "No privacy qualification or change to the earlier rejected policy follows from this recount."])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases",type=Path)
    parser.add_argument("result",type=Path)
    parser.add_argument("--rehearsal",action="store_true",help="require four public-development ledgers instead of 512")
    parser.add_argument("--output",type=Path,help="create a new public recount receipt; never overwrite")
    args=parser.parse_args()
    require(args.cases.name == "cases.json" and args.result.name == "result.json","input filename order")
    cases,cases_sha=parse_public(args.cases)
    summary,summary_sha=parse_public(args.result)
    receipt=recount(cases,summary,args.rehearsal)
    receipt.update(checked_utc=datetime.now(timezone.utc).isoformat(),cases_sha256=cases_sha,result_sha256=summary_sha,
                   recount_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    text=json.dumps(receipt,indent=2,allow_nan=False)+"\n"
    if args.output:
        require(not args.output.is_symlink(),"unsafe output path")
        with args.output.open("x",encoding="utf-8") as stream:
            stream.write(text)
    print(text,end="")


if __name__ == "__main__":
    main()
