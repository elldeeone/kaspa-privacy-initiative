"""Pure source/recipe audit; not a Circom parser or an R1CS check."""
from __future__ import annotations

import hashlib
import itertools
import json
import math
import re

AUTHORITY_SHA = "e5b158ec4cc88afa8be35ca8758140bb9c1e7899c31d83572ed20f30b824b68b"
PLAN_SHA = "458451f62e00bade1a7207b312ded0081ae05ac526c9c46318d54f6c5ddb2bc1"
HANDOFF_SHA = "284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218"
SHARED = ["anchor", "evaluationHeight", "testTag", "chainId", "poolId", "profileId", "roleId", "assetTag"]
PUBLIC = SHARED + ["NF", "tuple", "feeTotal"]
SHAPES = {**{k: () for k in SHARED}, "NF": (2,), "tuple": (4, 520), "feeTotal": ()}
PRIVATE = {
    "owner_nf": (2,), "owner_commitmentsOut": (2, 2),
    "owner_publicKeyBytes": (2, 2, 32), "owner_signatureR8Bytes": (2, 2, 32),
    "owner_signatureSBytes": (2, 32), "owner_outputNPK": (2, 2),
    "owner_valueOut": (2, 2), "owner_outputTuple": (2, 2, 520),
    **{"owner_" + k: (2,) for k in ["nullifyingKey", "inputRandom", "inputSompi", "leafIndex", "siblingCM", "feeSompi", "nonce", "validFrom", "validUntil"]},
    "U": (2, 2), "V": (4, 4),
}


def need(ok, label):
    if not ok:
        raise ValueError(label)


def uncomment(raw: bytes) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", raw.decode(), flags=re.S)


def template_body(source: str) -> str:
    hit = re.search(r"\btemplate\s+TwoOwnerAggregate\s*\(\s*\)\s*\{", source)
    need(hit is not None, "outer_template")
    start = hit.end()
    depth = 1
    for i in range(start, len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if depth == 0:
            return source[start:i]
    raise ValueError("outer_unclosed")


def audit_interface(wrapper: bytes, library: bytes, original: bytes):
    need(hashlib.sha256(original).hexdigest() == AUTHORITY_SHA, "authority_pin")
    need(original.count(b"component main") == 1, "original_main_once")
    prefix = original[:original.index(b"component main")]
    need(library == prefix, "exact_template_prefix")
    need(not re.search(r"\bcomponent\s+main\b", uncomment(library)), "library_has_main")
    source = uncomment(wrapper)
    mains = list(re.finditer(r"\bcomponent\s+main\b", source))
    need(len(mains) == 1, "outer_main_once")
    main = re.search(r"\bcomponent\s+main\s*\{\s*public\s*\[([^]]*)\]\s*\}\s*=\s*TwoOwnerAggregate\s*\(\s*\)\s*;", source)
    need(main is not None, "main_public_form")
    names = [n.strip() for n in main.group(1).split(",")]
    need(names == PUBLIC, "public_list_exact")
    body = template_body(source)
    need(not re.search(r"\bsignal\s+output\b", body), "no_outer_outputs")
    declarations = []
    for match in re.finditer(r"\bsignal\s+input\s+([A-Za-z_][A-Za-z_0-9]*)([^;]*);", body):
        suffix = match.group(2).strip()
        need(re.fullmatch(r"(?:\[\d+\])*", suffix) is not None, "literal_input_shape")
        declarations.append((match.group(1), tuple(map(int, re.findall(r"\[(\d+)\]", suffix)))))
    declared = dict(declarations)
    need(len(declared) == len(declarations), "input_declarations_unique")
    need(declared == {**SHAPES, **PRIVATE}, "exact_public_and_private_inputs")
    need([k for k, _ in declarations if k in PUBLIC] == PUBLIC, "public_declaration_order")
    count = sum(math.prod(SHAPES[k]) for k in PUBLIC)
    need(count == 2091, "public_arity")
    flattened = []
    for key in PUBLIC:
        indices = itertools.product(*(range(n) for n in SHAPES[key]))
        flattened.extend("main." + key + "".join(f"[{i}]" for i in ix) for ix in indices)
    need(len(flattened) == count, "public_flatten_count")
    return {"outputs": 0, "publicInputFields": count, "publicNames": PUBLIC,
            "privateInputDeclarations": len(PRIVATE), "flattenedPublicSymbols": flattened,
            "librarySHA256": hashlib.sha256(library).hexdigest(),
            "classification": "PURE_TEXT_SELECTION_AUDIT_NOT_COMPILATION_OR_PRIVACY"}


def audit_recipe(raw: bytes):
    recipe = json.loads(raw)
    need(recipe["schema"] == "two-owner-aggregate-finite-fixture/v1", "recipe_schema")
    need(recipe["planSHA256"] == PLAN_SHA and recipe["handoffSHA256"] == HANDOFF_SHA, "recipe_input_pins")
    need(recipe["authoritySourceSHA256"] == AUTHORITY_SHA, "recipe_authority_pin")
    need(recipe["publicFields"] == PUBLIC and recipe["expectedPublicFieldCount"] == 2091 and recipe["expectedOutputs"] == 0, "recipe_public_interface")
    rows = recipe["cases"]
    ids = [f"P{i:02d}" for i in range(1, 8)] + [f"N{i:02d}" for i in range(1, 23)]
    need([x["id"] for x in rows] == ids, "recipe_exact_ids")
    need(all(x["expectedAccepted"] is (i < 7) and x["actualCheckerRequired"] is True for i, x in enumerate(rows)), "recipe_exact_expectations")
    need(all(isinstance(x["mutation"], str) and x["mutation"] for x in rows), "recipe_mutations_recorded")
    need(recipe["staticInputs"]["expectedRows"] == 29 and recipe["staticInputs"]["expectedAccepts"] == 7 and recipe["staticInputs"]["expectedRejects"] == 22, "recipe_counts")
    return {"rows": 29, "accepted": 7, "rejected": 22, "actualR1csRequired": 29,
            "identicalReplayRow": "P07_ACCEPT_NO_SPENT_STATE"}
